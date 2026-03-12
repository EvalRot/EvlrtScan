package engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import template.ScanTemplate;
import template.detection.DetectionEngine;
import template.detection.DetectionRule;
import template.detection.rules.DifferentialDetectionRule;
import template.detection.rules.SmartDiffDetectionRule;
import template.detection.smartdiff.*;

import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Thread pool that continuously pulls ScanTasks from the ScanQueue
 * and executes them: inject payload → send request → detect → report result.
 */
public class ScanWorkerPool {
    private static final Logger log = Logger.getLogger(ScanWorkerPool.class.getName());

    private final ScanQueue queue;
    private final MontoyaApi api;
    private final PayloadInjector injector = new PayloadInjector();
    private final SimpleRateLimiter rateLimiter;

    private volatile ExecutorService pool;
    private volatile boolean running = false;
    private volatile int threadCount;

    public ScanWorkerPool(ScanQueue queue, MontoyaApi api, int threadCount, double maxRps) {
        this.queue = queue;
        this.api = api;
        this.threadCount = threadCount;
        this.rateLimiter = new SimpleRateLimiter(maxRps);
    }

    public void start() {
        running = true;
        pool = Executors.newFixedThreadPool(threadCount, r -> {
            Thread t = new Thread(r, "evlrtscan-worker");
            t.setDaemon(true);
            return t;
        });
        for (int i = 0; i < threadCount; i++) {
            pool.submit(this::workerLoop);
        }
    }

    public void shutdown() {
        running = false;
        if (pool != null) {
            pool.shutdownNow();
            try {
                pool.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Update the rate limit on the fly. */
    public void setMaxRps(double rps) {
        rateLimiter.setMaxRequestsPerSecond(rps);
    }

    /** Restart with new thread count. */
    public void setThreadCount(int count) {
        this.threadCount = count;
        if (running) {
            shutdown();
            start();
        }
    }

    private void workerLoop() {
        while (running && !Thread.currentThread().isInterrupted()) {
            try {
                ScanTask task = queue.take(); // blocks until task available
                executeTask(task);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.warning("Worker error: " + e.getMessage());
            }
        }
    }

    private void executeTask(ScanTask task) {
        // Dispatch group tasks to their own handler
        if (task instanceof GroupScanTask groupTask) {
            executeGroupTask(groupTask);
            return;
        }
        ScanJob job = task.getParentJob();

        // Skip if job cancelled
        if (job.getStatus() == ScanJob.JobStatus.CANCELLED) {
            task.setStatus(ScanTask.Status.CANCELLED);
            job.onTaskComplete(task);
            return;
        }

        task.setStatus(ScanTask.Status.RUNNING);

        try {
            // Rate limiting
            rateLimiter.acquire();

            // Build modified request (encoding-aware)
            var modifiedReq = injector.inject(
                    task.getOriginalRequest(),
                    task.getInsertionPoint(),
                    task.getPayload(),
                    task.getTemplate().getInjectionStrategy(),
                    task.getForcedEncoding(),
                    task.getJsonType());
            task.setModifiedRequest(modifiedReq);

            // Send request — TimingData is included in the response automatically
            HttpRequestResponse actual = api.http().sendRequest(modifiedReq);
            task.setActualResponse(actual);

            // Store elapsed time from Montoya's TimingData
            var timingOpt = actual.timingData();
            if (timingOpt.isPresent()) {
                task.setElapsedMs(timingOpt.get()
                        .timeBetweenRequestSentAndEndOfResponse().toMillis());
            }

            // Evaluate detection rules
            List<DetectionRule> rules = DetectionEngine.buildRules(task.getTemplate().getDetection());
            HttpRequestResponse baseline = task.getBaselineResponse();
            boolean hit = DetectionEngine.evaluate(
                    task.getTemplate().getDetection(), rules, baseline, actual, task.getPayload());

            if (hit) {
                task.setStatus(ScanTask.Status.HIT);
                // Identify which rule fired
                for (int i = 0; i < rules.size(); i++) {
                    if (rules.get(i).matches(baseline, actual, task.getPayload())) {
                        task.setMatchedRule(task.getTemplate().getDetection().getRules().get(i).getType());
                        break;
                    }
                }
            } else {
                task.setStatus(ScanTask.Status.MISS);
            }

            // Per-task delay
            int delayMs = job.getOptions().getDelayMs();
            if (delayMs > 0)
                Thread.sleep(delayMs);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            task.setStatus(ScanTask.Status.CANCELLED);
        } catch (Exception e) {
            task.setStatus(ScanTask.Status.ERROR);
            task.setErrorMessage(e.getMessage());
            log.warning("Task error [" + task.getTemplate().getId() + " → "
                    + task.getInsertionPoint().getDisplayLabel() + "]: " + e.getMessage());
        } finally {
            job.onTaskComplete(task);
        }
    }

    /**
     * Execute a GroupScanTask: send one request per payload in the group,
     * collect responses, then evaluate the detection expression.
     * Supports both simple differential and smart_diff rules.
     */
    private void executeGroupTask(GroupScanTask task) {
        ScanJob job = task.getParentJob();

        if (job.getStatus() == ScanJob.JobStatus.CANCELLED) {
            task.setStatus(ScanTask.Status.CANCELLED);
            job.onTaskComplete(task);
            return;
        }

        task.setStatus(ScanTask.Status.RUNNING);

        try {
            var detection = task.getTemplate().getDetection();
            List<DetectionRule> rules = DetectionEngine.buildRules(detection);

            // Check if any rule is smart_diff
            SmartDiffDetectionRule smartRule = null;
            int smartRuleIndex = -1;
            for (int i = 0; i < rules.size(); i++) {
                if (rules.get(i) instanceof SmartDiffDetectionRule sdr) {
                    smartRule = sdr;
                    smartRuleIndex = i;
                    break;
                }
            }

            if (smartRule != null) {
                executeSmartDiffPath(task, job, smartRule, smartRuleIndex, detection);
            } else {
                executeDifferentialPath(task, job, rules, detection);
            }

            // Per-task delay
            int delayMs = job.getOptions().getDelayMs();
            if (delayMs > 0)
                Thread.sleep(delayMs);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            task.setStatus(ScanTask.Status.CANCELLED);
        } catch (Exception e) {
            task.setStatus(ScanTask.Status.ERROR);
            task.setErrorMessage(e.getMessage());
            log.warning("GroupTask error [" + task.getTemplate().getId() + " → "
                    + task.getInsertionPoint().getDisplayLabel() + "]: " + e.getMessage());
        } finally {
            job.onTaskComplete(task);
        }
    }

    /**
     * Standard differential detection path (simple body diff ratio).
     */
    private void executeDifferentialPath(GroupScanTask task, ScanJob job,
            List<DetectionRule> rules, ScanTemplate.Detection detection)
            throws InterruptedException {

        for (ScanTemplate.PayloadGroupEntry entry : task.getGroup()) {
            rateLimiter.acquire();
            var modifiedReq = injector.inject(
                    task.getOriginalRequest(),
                    task.getInsertionPoint(),
                    entry.getValue(),
                    task.getTemplate().getInjectionStrategy(),
                    task.getForcedEncoding(),
                    entry.getJsonType());
            HttpRequestResponse response = api.http().sendRequest(modifiedReq);
            task.putResponse(entry.getId(), response);
        }

        Map<String, HttpRequestResponse> fullMap = task.buildFullResponseMap();

        boolean hit = false;
        String matchedRuleType = null;
        for (int i = 0; i < rules.size(); i++) {
            DetectionRule rule = rules.get(i);
            if (rule instanceof DifferentialDetectionRule diffRule) {
                if (diffRule.matchesDifferential(fullMap)) {
                    hit = true;
                    matchedRuleType = detection.getRules().get(i).getType();
                    break;
                }
            }
        }

        if (hit) {
            task.setStatus(ScanTask.Status.HIT);
            task.setMatchedRule(matchedRuleType);
        } else {
            task.setStatus(ScanTask.Status.MISS);
        }
    }

    /**
     * SmartDiff detection path:
     * 1. Send 2 extra baselines to build Dynamic Mask
     * 2. Send probe request to build Reflection Mask
     * 3. Send payload requests, parse & mask, compute Jaccard
     * 4. Evaluate expression
     */
    private void executeSmartDiffPath(GroupScanTask task, ScanJob job,
            SmartDiffDetectionRule smartRule, int smartRuleIndex,
            ScanTemplate.Detection detection)
            throws InterruptedException {

        // --- Step 1: Dynamic Mask (Shared per Job) ---
        HttpRequestResponse baseline = task.getBaselineResponse();
        String baselineBody = baseline != null && baseline.hasResponse()
                ? baseline.response().bodyToString()
                : "";
        String contentType = baseline != null && baseline.hasResponse()
                ? baseline.response().headerValue("Content-Type")
                : null;

        Set<String> dynamicMask = job.getCachedDynamicMask();
        if (dynamicMask == null) {
            synchronized (job) {
                dynamicMask = job.getCachedDynamicMask();
                if (dynamicMask == null) {
                    rateLimiter.acquire();
                    HttpRequestResponse resp1 = api.http().sendRequest(task.getOriginalRequest());
                    rateLimiter.acquire();
                    HttpRequestResponse resp2 = api.http().sendRequest(task.getOriginalRequest());

                    String body1 = resp1.hasResponse() ? resp1.response().bodyToString() : "";
                    String body2 = resp2.hasResponse() ? resp2.response().bodyToString() : "";

                    dynamicMask = SmartDiffEngine.buildDynamicMask(
                            contentType, baselineBody, body1, body2);
                    job.setCachedDynamicMask(dynamicMask);
                }
            }
        }

        // --- Step 2: Reflection Mask (Shared per Insertion Point) ---
        Set<String> reflectionMask = job.getCachedReflectionMask(task.getInsertionPoint());
        if (reflectionMask == null) {
            synchronized (job) {
                reflectionMask = job.getCachedReflectionMask(task.getInsertionPoint());
                if (reflectionMask == null) {
                    String marker = "EVLRT_PROBE_" + System.nanoTime();
                    rateLimiter.acquire();
                    var probeReq = injector.inject(
                            task.getOriginalRequest(),
                            task.getInsertionPoint(),
                            marker,
                            task.getTemplate().getInjectionStrategy(),
                            task.getForcedEncoding(),
                            "keep");
                    HttpRequestResponse probeResp = api.http().sendRequest(probeReq);
                    String probeBody = probeResp.hasResponse() ? probeResp.response().bodyToString() : "";

                    reflectionMask = SmartDiffEngine.buildReflectionMask(
                            contentType, probeBody, marker);
                    job.setCachedReflectionMask(task.getInsertionPoint(), reflectionMask);
                }
            }
        }

        // --- Step 3: Parse baseline and apply Dynamic Mask ---
        ParsedResponse baselineParsed = ResponseParser.parse(baselineBody, contentType);
        ParsedResponse maskedBaseline = baselineParsed.applyMask(dynamicMask);

        // --- Step 4: Send payload requests, parse, mask, compute Jaccard ---
        Map<String, SmartDiffResult> smartResults = new LinkedHashMap<>();

        for (ScanTemplate.PayloadGroupEntry entry : task.getGroup()) {
            rateLimiter.acquire();
            var modifiedReq = injector.inject(
                    task.getOriginalRequest(),
                    task.getInsertionPoint(),
                    entry.getValue(),
                    task.getTemplate().getInjectionStrategy(),
                    task.getForcedEncoding(),
                    entry.getJsonType());
            HttpRequestResponse payloadResp = api.http().sendRequest(modifiedReq);
            task.putResponse(entry.getId(), payloadResp);

            String payloadBody = payloadResp.hasResponse()
                    ? payloadResp.response().bodyToString()
                    : "";
            ParsedResponse payloadParsed = ResponseParser.parse(payloadBody, contentType);
            ParsedResponse maskedPayload = payloadParsed.applyMasks(dynamicMask, reflectionMask);

            SmartDiffResult result = SmartDiffEngine.compare(maskedBaseline, maskedPayload);
            smartResults.put("baseline~" + entry.getId(), result);

            log.fine("SmartDiff [" + entry.getId() + "]: " + result);
        }

        // Cross-payload comparisons (e.g. p1~p2)
        List<ScanTemplate.PayloadGroupEntry> groupEntries = task.getGroup();
        for (int i = 0; i < groupEntries.size(); i++) {
            for (int j = i + 1; j < groupEntries.size(); j++) {
                String idA = groupEntries.get(i).getId();
                String idB = groupEntries.get(j).getId();

                HttpRequestResponse respA = task.getResponses().get(idA);
                HttpRequestResponse respB = task.getResponses().get(idB);

                String bodyA = respA != null && respA.hasResponse()
                        ? respA.response().bodyToString()
                        : "";
                String bodyB = respB != null && respB.hasResponse()
                        ? respB.response().bodyToString()
                        : "";

                ParsedResponse parsedA = ResponseParser.parse(bodyA, contentType)
                        .applyMasks(dynamicMask, reflectionMask);
                ParsedResponse parsedB = ResponseParser.parse(bodyB, contentType)
                        .applyMasks(dynamicMask, reflectionMask);

                SmartDiffResult crossResult = SmartDiffEngine.compare(parsedA, parsedB);
                smartResults.put(idA + "~" + idB, crossResult);
            }
        }

        // --- Step 5: Evaluate expression ---
        // Build individual response map for status/header access
        Map<String, HttpRequestResponse> responseMap = new LinkedHashMap<>();
        if (baseline != null) responseMap.put("baseline", baseline);
        task.getResponses().forEach(responseMap::put);

        boolean hit = smartRule.matchesSmart(smartResults, responseMap);

        if (hit) {
            task.setStatus(ScanTask.Status.HIT);
            task.setMatchedRule(detection.getRules().get(smartRuleIndex).getType());
        } else {
            task.setStatus(ScanTask.Status.MISS);
        }
    }
}
