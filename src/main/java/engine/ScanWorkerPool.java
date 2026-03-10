package engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionEngine;
import template.detection.DetectionRule;

import java.util.List;
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
                    task.getForcedEncoding());
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
}
