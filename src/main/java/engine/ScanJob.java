package engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import template.ScanTemplate;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * A single scan operation initiated by the user from the Scan Dialog.
 * Contains all tasks for a given request × templates × insertion points.
 */
public class ScanJob {
    public enum JobStatus {
        PENDING, RUNNING, PAUSED, COMPLETED, CANCELLED
    }

    private final String id;
    private final HttpRequest originalRequest;
    private final String targetDescription; // e.g. "POST https://target.com/api/login"
    private final List<ScanTemplate> templates;
    private final List<InsertionPoint> selectedPoints;
    private final ScanOptions options;
    private final long createdAt = System.currentTimeMillis();

    private volatile JobStatus status = JobStatus.PENDING;
    private final AtomicInteger totalTasks = new AtomicInteger(0);
    private final AtomicInteger completedTasks = new AtomicInteger(0);

    private final List<ScanFinding> findings = new CopyOnWriteArrayList<>();

    // SmartDiff Caches to prevent redundant requests across multiple templates/insertion points
    private volatile Set<String> cachedDynamicMask;
    private final Map<InsertionPoint, Set<String>> cachedReflectionMasks = new java.util.concurrent.ConcurrentHashMap<>();

    // Callback invoked after each task completes (for UI updates)
    private Consumer<ScanJob> progressListener;

    public ScanJob(HttpRequest originalRequest, String targetDescription,
            List<ScanTemplate> templates, List<InsertionPoint> selectedPoints,
            ScanOptions options) {
        this.id = UUID.randomUUID().toString().substring(0, 8);
        this.originalRequest = originalRequest;
        this.targetDescription = targetDescription;
        this.templates = Collections.unmodifiableList(templates);
        this.selectedPoints = Collections.unmodifiableList(selectedPoints);
        this.options = options;
    }

    /** Called by ScanEngine after generating all tasks. */
    public void setTotalTasks(int count) {
        totalTasks.set(count);
    }

    /** Called by worker after each task completes. */
    public void onTaskComplete(ScanTask task) {
        completedTasks.incrementAndGet();

        if (task.getStatus() == ScanTask.Status.HIT) {
            findings.add(new ScanFinding(task));
        }

        if (completedTasks.get() >= totalTasks.get() && totalTasks.get() > 0) {
            status = JobStatus.COMPLETED;
        }

        if (progressListener != null)
            progressListener.accept(this);
    }

    // ---- Getters -------------------------------------------------------
    public String getId() {
        return id;
    }

    public HttpRequest getOriginalRequest() {
        return originalRequest;
    }

    public String getTargetDescription() {
        return targetDescription;
    }

    public List<ScanTemplate> getTemplates() {
        return templates;
    }

    public List<InsertionPoint> getSelectedPoints() {
        return selectedPoints;
    }

    public ScanOptions getOptions() {
        return options;
    }

    public JobStatus getStatus() {
        return status;
    }

    public void setStatus(JobStatus status) {
        this.status = status;
    }

    public int getTotalTasks() {
        return totalTasks.get();
    }

    public int getCompletedTasks() {
        return completedTasks.get();
    }

    public List<ScanFinding> getFindings() {
        return Collections.unmodifiableList(findings);
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setProgressListener(Consumer<ScanJob> listener) {
        this.progressListener = listener;
    }

    public int getProgressPercent() {
        int total = totalTasks.get();
        if (total == 0)
            return 0;
        return (int) ((completedTasks.get() * 100L) / total);
    }

    // ---- SmartDiff Caches ----------------------------------------------
    public Set<String> getCachedDynamicMask() {
        return cachedDynamicMask;
    }

    public void setCachedDynamicMask(Set<String> mask) {
        this.cachedDynamicMask = mask;
    }

    public Set<String> getCachedReflectionMask(InsertionPoint point) {
        return cachedReflectionMasks.get(point);
    }

    public void setCachedReflectionMask(InsertionPoint point, Set<String> mask) {
        cachedReflectionMasks.put(point, mask);
    }
}
