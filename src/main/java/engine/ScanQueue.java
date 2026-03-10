package engine;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;

/**
 * Global scan task queue shared across all active ScanJobs.
 * Uses a LinkedBlockingQueue so workers block when empty.
 */
public class ScanQueue {
    private final LinkedBlockingQueue<ScanTask> queue = new LinkedBlockingQueue<>();
    private final CopyOnWriteArrayList<ScanJob> activeJobs = new CopyOnWriteArrayList<>();

    public void enqueue(ScanTask task) {
        queue.offer(task);
    }

    /**
     * Workers call this — blocks until a task is available or thread is
     * interrupted.
     */
    public ScanTask take() throws InterruptedException {
        return queue.take();
    }

    /** Non-blocking poll — returns null if empty. */
    public ScanTask poll() {
        return queue.poll();
    }

    /** Remove all pending tasks belonging to a specific job (cancel). */
    public void cancelJob(ScanJob job) {
        queue.removeIf(task -> task.getParentJob() == job);
        job.setStatus(ScanJob.JobStatus.CANCELLED);
    }

    /** Remove all tasks from queue. */
    public void clear() {
        queue.clear();
    }

    public int size() {
        return queue.size();
    }

    public void registerJob(ScanJob job) {
        activeJobs.add(job);
    }

    public void unregisterJob(ScanJob job) {
        activeJobs.remove(job);
    }

    public List<ScanJob> getActiveJobs() {
        return activeJobs;
    }
}
