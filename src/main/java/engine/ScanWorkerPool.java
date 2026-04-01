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
import java.util.concurrent.*;
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
    private volatile int maxRetries;
    private volatile int requestTimeoutSec;

    public ScanWorkerPool(ScanQueue queue, MontoyaApi api, int threadCount, double maxRps,
            int maxRetries, int requestTimeoutSec) {
        this.queue = queue;
        this.api = api;
        this.threadCount = threadCount;
        this.rateLimiter = new SimpleRateLimiter(maxRps);
        this.maxRetries = maxRetries;
        this.requestTimeoutSec = requestTimeoutSec;
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

    /** Update max retries on the fly. */
    public void setMaxRetries(int retries) {
        this.maxRetries = retries;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    /** Update request timeout on the fly. */
    public void setRequestTimeoutSec(int sec) {
        this.requestTimeoutSec = sec;
    }

    public int getRequestTimeoutSec() {
        return requestTimeoutSec;
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

            // Send request with retry logic
            HttpRequestResponse actual = sendWithRetry(
                    modifiedReq, task.getParentJob(),
                    task.getTemplate().getId(),
                    task.getInsertionPoint().getDisplayLabel());

            if (actual == null) {
                // All retries exhausted — check if job was failed/cancelled
                if (job.getStatus() == ScanJob.JobStatus.FAILED
                        || job.getStatus() == ScanJob.JobStatus.CANCELLED) {
                    task.setStatus(ScanTask.Status.CANCELLED);
                } else {
                    task.setStatus(ScanTask.Status.ERROR);
                    task.setErrorMessage("Request timed out after " + maxRetries + " retries");
                }
                return; // skip detection
            }

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

        String templateId = task.getTemplate().getId();
        String pointLabel = task.getInsertionPoint().getDisplayLabel();

        for (ScanTemplate.PayloadGroupEntry entry : task.getGroup()) {
            if (job.getStatus() == ScanJob.JobStatus.FAILED) {
                task.setStatus(ScanTask.Status.CANCELLED);
                return;
            }
            var modifiedReq = injector.inject(
                    task.getOriginalRequest(),
                    task.getInsertionPoint(),
                    entry.getValue(),
                    task.getTemplate().getInjectionStrategy(),
                    task.getForcedEncoding(),
                    entry.getJsonType());
            HttpRequestResponse response = sendWithRetry(modifiedReq, job, templateId, pointLabel);
            if (response == null) {
                task.setStatus(job.getStatus() == ScanJob.JobStatus.FAILED
                        ? ScanTask.Status.CANCELLED
                        : ScanTask.Status.ERROR);
                if (task.getStatus() == ScanTask.Status.ERROR)
                    task.setErrorMessage("Request timed out after retries");
                return;
            }
            task.putResponse(entry.getId(), response);
        }

        Map<String, HttpRequestResponse> fullMap = task.buildFullResponseMap();

        boolean hit = false;
        String matchedRuleType = null;
        List<String> matchedTriggers = new ArrayList<>();

        for (int i = 0; i < rules.size(); i++) {
            DetectionRule rule = rules.get(i);
            if (rule instanceof DifferentialDetectionRule diffRule) {
                if (diffRule.matchesDifferential(fullMap, matchedTriggers)) {
                    hit = true;
                    matchedRuleType = detection.getRules().get(i).getType();
                    break;
                }
            }
        }

        if (hit) {
            task.setStatus(ScanTask.Status.HIT);
            task.setMatchedRule(matchedRuleType);

            // Set basic diff score
            for (DetectionRule rule : rules) {
                if (rule instanceof DifferentialDetectionRule diffRule) {
                    task.setDiffScores(String.format("Rules [Threshold: %.2f]", diffRule.getThreshold()));
                    break;
                }
            }

            if (!matchedTriggers.isEmpty()) {
                task.setTriggerReason(String.join(" OR ", matchedTriggers));
            }
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
                    String templateId = task.getTemplate().getId();
                    String pointLabel = task.getInsertionPoint().getDisplayLabel();

                    HttpRequestResponse resp1 = sendWithRetry(
                            task.getOriginalRequest(), job, templateId, pointLabel);
                    if (resp1 == null) {
                        task.setStatus(ScanTask.Status.CANCELLED);
                        return;
                    }

                    HttpRequestResponse resp2 = sendWithRetry(
                            task.getOriginalRequest(), job, templateId, pointLabel);
                    if (resp2 == null) {
                        task.setStatus(ScanTask.Status.CANCELLED);
                        return;
                    }

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
                    var probeReq = injector.inject(
                            task.getOriginalRequest(),
                            task.getInsertionPoint(),
                            marker,
                            task.getTemplate().getInjectionStrategy(),
                            task.getForcedEncoding(),
                            "keep");
                    HttpRequestResponse probeResp = sendWithRetry(
                            probeReq, job, task.getTemplate().getId(),
                            task.getInsertionPoint().getDisplayLabel());
                    if (probeResp == null) {
                        task.setStatus(ScanTask.Status.CANCELLED);
                        return;
                    }

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
            if (job.getStatus() == ScanJob.JobStatus.FAILED) {
                task.setStatus(ScanTask.Status.CANCELLED);
                return;
            }
            var modifiedReq = injector.inject(
                    task.getOriginalRequest(),
                    task.getInsertionPoint(),
                    entry.getValue(),
                    task.getTemplate().getInjectionStrategy(),
                    task.getForcedEncoding(),
                    entry.getJsonType());
            HttpRequestResponse payloadResp = sendWithRetry(
                    modifiedReq, job, task.getTemplate().getId(),
                    task.getInsertionPoint().getDisplayLabel());
            if (payloadResp == null) {
                task.setStatus(job.getStatus() == ScanJob.JobStatus.FAILED
                        ? ScanTask.Status.CANCELLED
                        : ScanTask.Status.ERROR);
                return;
            }
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
        if (baseline != null)
            responseMap.put("baseline", baseline);
        task.getResponses().forEach(responseMap::put);

        List<String> matchedTriggers = new ArrayList<>();
        boolean hit = smartRule.matchesSmart(smartResults, responseMap, matchedTriggers);

        if (hit) {
            task.setStatus(ScanTask.Status.HIT);
            task.setMatchedRule(detection.getRules().get(smartRuleIndex).getType());

            // Build scores string
            StringBuilder scores = new StringBuilder();
            scores.append(String.format("Rules [C: %.2f, S: %.2f] | ",
                    smartRule.getContentThreshold(), smartRule.getStructureThreshold()));
            smartResults.forEach((k, v) -> {
                scores.append(String.format("%s [C: %.2f, S: %.2f] ",
                        k, v.getContentSimilarity(), v.getStructureSimilarity()));
            });
            task.setDiffScores(scores.toString().trim());

            if (!matchedTriggers.isEmpty()) {
                task.setTriggerReason(String.join(" OR ", matchedTriggers));
            }
        } else {
            task.setStatus(ScanTask.Status.MISS);
        }
    }

    // ---- Retry / Timeout helpers ----------------------------------------

    /**
     * Send a request with a timeout. Returns null if the request times out.
     */
    private HttpRequestResponse sendWithTimeout(burp.api.montoya.http.message.requests.HttpRequest request)
            throws InterruptedException {
        if (requestTimeoutSec <= 0) {
            return api.http().sendRequest(request);
        }

        CompletableFuture<HttpRequestResponse> future = CompletableFuture.supplyAsync(
                () -> api.http().sendRequest(request));
        try {
            return future.get(requestTimeoutSec, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            return null;
        } catch (ExecutionException e) {
            if (e.getCause() instanceof RuntimeException re)
                throw re;
            throw new RuntimeException(e.getCause());
        }
    }

    /**
     * Send a request with retry logic.
     * Returns null if all retries are exhausted AND the canary check also fails
     * (in which case the job is marked FAILED).
     */
    private HttpRequestResponse sendWithRetry(
            burp.api.montoya.http.message.requests.HttpRequest request,
            ScanJob job, String templateId, String pointLabel)
            throws InterruptedException {

        // Attempt 1 + maxRetries
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            if (job.getStatus() == ScanJob.JobStatus.FAILED
                    || job.getStatus() == ScanJob.JobStatus.CANCELLED) {
                return null;
            }

            rateLimiter.acquire();
            HttpRequestResponse resp = sendWithTimeout(request);
            if (resp != null) {
                return resp;
            }

            if (attempt < maxRetries) {
                log.warning("Timeout on attempt " + (attempt + 1) + "/" + (maxRetries + 1)
                        + " [" + templateId + " → " + pointLabel + "], retrying...");
            }
        }

        // All retries exhausted — send canary (same request, one more time)
        log.warning("All retries exhausted [" + templateId + " → " + pointLabel
                + "], sending canary request...");
        rateLimiter.acquire();
        HttpRequestResponse canary = sendWithTimeout(request);

        if (canary != null) {
            // Canary succeeded — server is alive, just this specific request was slow
            log.info("Canary succeeded [" + templateId + " → " + pointLabel
                    + "], continuing scan");
            return canary;
        }

        // Canary also failed — server is unresponsive, fail the job
        String reason = String.format("[%1$tF %1$tT] Server unresponsive — template: %2$s, point: %3$s",
                new java.util.Date(), templateId, pointLabel);
        log.severe("SCAN FAILED: " + reason);
        job.setFailureReason(reason);
        job.setStatus(ScanJob.JobStatus.FAILED);
        return null;
    }
}
