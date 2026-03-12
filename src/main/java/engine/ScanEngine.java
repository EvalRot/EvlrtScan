package engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import template.ScanTemplate;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Top-level scan orchestrator.
 * Creates ScanJobs, generates ScanTasks, pushes to queue.
 * Manages the ScanWorkerPool lifecycle.
 */
public class ScanEngine {
    private static final Logger log = Logger.getLogger(ScanEngine.class.getName());

    private final MontoyaApi api;
    private final ScanQueue queue = new ScanQueue();
    private ScanWorkerPool workerPool;

    // All jobs ever created (for the ActiveScans panel)
    private final CopyOnWriteArrayList<ScanJob> allJobs = new CopyOnWriteArrayList<>();

    // Global listener for UI updates
    private final CopyOnWriteArrayList<Consumer<ScanJob>> globalProgressListeners = new CopyOnWriteArrayList<>();

    public ScanEngine(MontoyaApi api, int threadCount, double maxRps) {
        this.api = api;
        this.workerPool = new ScanWorkerPool(queue, api, threadCount, maxRps);
    }

    public void start() {
        workerPool.start();
        log.info("EvlrtScan engine started");
    }

    public void shutdown() {
        queue.clear();
        workerPool.shutdown();
        log.info("EvlrtScan engine stopped");
    }

    /**
     * Launch a new scan job from the Scan Dialog.
     * Sends baseline request, generates all tasks, enqueues them.
     */
    public ScanJob submitJob(HttpRequest request, List<ScanTemplate> templates,
            List<InsertionPoint> selectedPoints, ScanOptions options) {
        String targetDesc = request.method() + " " + request.httpService().host() + request.path();
        ScanJob job = new ScanJob(request, targetDesc, templates, selectedPoints, options);

        if (!globalProgressListeners.isEmpty()) {
            job.setProgressListener(j -> globalProgressListeners.forEach(l -> l.accept(j)));
        }

        allJobs.add(job);
        queue.registerJob(job);
        job.setStatus(ScanJob.JobStatus.RUNNING);

        // Run baseline + task generation in background to avoid blocking UI
        Thread prepThread = new Thread(() -> prepareAndEnqueue(job, request, templates, selectedPoints),
                "evlrtscan-prep");
        prepThread.setDaemon(true);
        prepThread.start();

        return job;
    }

    private void prepareAndEnqueue(ScanJob job, HttpRequest request,
            List<ScanTemplate> templates, List<InsertionPoint> points) {
        try {
            // PHASE 1: Baseline request
            HttpRequestResponse baseline = null;
            boolean needsBaseline = templates.stream()
                    .anyMatch(t -> t.getDetection() != null && t.getDetection().isBaseline());

            if (needsBaseline) {
                baseline = api.http().sendRequest(request);
                log.fine("Baseline sent for: " + job.getTargetDescription());
            }

            final HttpRequestResponse finalBaseline = baseline;

            // PHASE 2: Generate tasks
            int taskCount = 0;
            for (ScanTemplate template : templates) {
                for (InsertionPoint point : points) {
                    // Detect encoding once per insertion point
                    var encoding = EncodingDetector.detect(point.getOriginalValue());
                    boolean needsUnicodeRetry = (point.getType() == InsertionPoint.Type.JSON_VALUE
                            && encoding == EncodingDetector.Encoding.PLAIN);

                    // --- Flat payloads: one task per payload ---
                    if (template.getPayloads() != null) {
                        for (ScanTemplate.PayloadEntry entry : template.getPayloads()) {
                            ScanTask task = new ScanTask(job, template, point, entry.getValue(),
                                    request, finalBaseline);
                            task.setJsonType(entry.getJsonType());
                            queue.enqueue(task);
                            taskCount++;

                            if (needsUnicodeRetry) {
                                ScanTask unicodeTask = new ScanTask(job, template, point, entry.getValue(),
                                        request, finalBaseline, EncodingDetector.Encoding.UNICODE);
                                unicodeTask.setJsonType(entry.getJsonType());
                                queue.enqueue(unicodeTask);
                                taskCount++;
                            }
                        }
                    }

                    // --- Payload group: one GroupScanTask per point ---
                    if (template.getPayloadGroup() != null && !template.getPayloadGroup().isEmpty()) {
                        GroupScanTask groupTask = new GroupScanTask(
                                job, template, point, template.getPayloadGroup(),
                                request, finalBaseline);
                        queue.enqueue(groupTask);
                        taskCount++;

                        if (needsUnicodeRetry) {
                            GroupScanTask unicodeGroup = new GroupScanTask(
                                    job, template, point, template.getPayloadGroup(),
                                    request, finalBaseline, EncodingDetector.Encoding.UNICODE);
                            queue.enqueue(unicodeGroup);
                            taskCount++;
                        }
                    }
                }
            }
            job.setTotalTasks(taskCount);
            log.info("Enqueued " + taskCount + " tasks for: " + job.getTargetDescription());

        } catch (Exception e) {
            log.severe("Failed to prepare job: " + e.getMessage());
            job.setStatus(ScanJob.JobStatus.CANCELLED);
        }
    }

    /** Count estimated total requests before starting. */
    public static int estimateRequests(List<ScanTemplate> templates, List<InsertionPoint> points) {
        return templates.stream().mapToInt(t -> t.getPayloads().size() * points.size()).sum();
    }

    public void cancelJob(ScanJob job) {
        queue.cancelJob(job);
    }

    public void pauseJob(ScanJob job) {
        job.setStatus(ScanJob.JobStatus.PAUSED);
    }

    public void resumeJob(ScanJob job) {
        job.setStatus(ScanJob.JobStatus.RUNNING);
    }

    public List<ScanJob> getAllJobs() {
        return allJobs;
    }

    public ScanQueue getQueue() {
        return queue;
    }

    public void addGlobalProgressListener(Consumer<ScanJob> listener) {
        this.globalProgressListeners.add(listener);
    }

    /** Reconfigure thread count on the fly. */
    public void setThreadCount(int count) {
        workerPool.setThreadCount(count);
    }

    public void setMaxRps(double rps) {
        workerPool.setMaxRps(rps);
    }
}
