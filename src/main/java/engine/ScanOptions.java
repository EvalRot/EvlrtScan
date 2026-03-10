package engine;

/**
 * Configurable options for a scan run (can be overridden per-job in the
 * dialog).
 */
public class ScanOptions {
    private int threadCount;
    private int delayMs;
    private int timeoutSeconds;
    private boolean followRedirects;
    private boolean scopeOnly;

    public ScanOptions() {
        // Defaults
        this.threadCount = 5;
        this.delayMs = 100;
        this.timeoutSeconds = 15;
        this.followRedirects = false;
        this.scopeOnly = true;
    }

    public ScanOptions(int threadCount, int delayMs, int timeoutSeconds,
            boolean followRedirects, boolean scopeOnly) {
        this.threadCount = threadCount;
        this.delayMs = delayMs;
        this.timeoutSeconds = timeoutSeconds;
        this.followRedirects = followRedirects;
        this.scopeOnly = scopeOnly;
    }

    public int getThreadCount() {
        return threadCount;
    }

    public void setThreadCount(int threadCount) {
        this.threadCount = threadCount;
    }

    public int getDelayMs() {
        return delayMs;
    }

    public void setDelayMs(int delayMs) {
        this.delayMs = delayMs;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    public void setFollowRedirects(boolean followRedirects) {
        this.followRedirects = followRedirects;
    }

    public boolean isScopeOnly() {
        return scopeOnly;
    }

    public void setScopeOnly(boolean scopeOnly) {
        this.scopeOnly = scopeOnly;
    }
}
