package engine;

/**
 * Simple token-bucket rate limiter to avoid overwhelming target servers or
 * WAFs.
 * Each call to acquire() blocks until the minimum interval since the last
 * request has passed.
 */
public class SimpleRateLimiter {
    private volatile long lastRequestNanos = 0L;
    private volatile long minIntervalNanos;

    /**
     * @param maxRequestsPerSecond Maximum number of requests per second globally.
     */
    public SimpleRateLimiter(double maxRequestsPerSecond) {
        this.minIntervalNanos = (long) (1_000_000_000.0 / maxRequestsPerSecond);
    }

    public synchronized void acquire() throws InterruptedException {
        long now = System.nanoTime();
        long waitNanos = minIntervalNanos - (now - lastRequestNanos);
        if (waitNanos > 0) {
            Thread.sleep(waitNanos / 1_000_000, (int) (waitNanos % 1_000_000));
        }
        lastRequestNanos = System.nanoTime();
    }

    public void setMaxRequestsPerSecond(double rps) {
        this.minIntervalNanos = (long) (1_000_000_000.0 / rps);
    }
}
