package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionRule;

/**
 * Fires when response body changes significantly compared to baseline
 * (diff-based detection).
 */
public class BodyDiffRule implements DetectionRule {
    private final double threshold; // 0.0 - 1.0, e.g. 0.3 = 30%

    public BodyDiffRule(double threshold) {
        this.threshold = threshold;
    }

    @Override
    public boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload) {
        if (baseline == null || !baseline.hasResponse())
            return false;
        if (actual == null || !actual.hasResponse())
            return false;

        String baseBody = baseline.response().bodyToString();
        String actualBody = actual.response().bodyToString();

        if (baseBody.isEmpty() && actualBody.isEmpty())
            return false;

        int maxLen = Math.max(baseBody.length(), actualBody.length());
        if (maxLen == 0)
            return false;

        int dist = levenshteinDistance(baseBody, actualBody, maxLen);
        double diffRatio = (double) dist / maxLen;
        return diffRatio >= threshold;
    }

    /**
     * Fast approximate Levenshtein distance capped at maxDist.
     * We use a simple character-level diff for performance.
     */
    private int levenshteinDistance(String a, String b, int cap) {
        // For large bodies, use a simplified line-based approach
        if (a.length() > 5000 || b.length() > 5000) {
            return approximateDiff(a, b, cap);
        }
        int m = a.length(), n = b.length();
        int[] dp = new int[n + 1];
        for (int j = 0; j <= n; j++)
            dp[j] = j;
        for (int i = 1; i <= m; i++) {
            int prev = dp[0];
            dp[0] = i;
            for (int j = 1; j <= n; j++) {
                int temp = dp[j];
                dp[j] = a.charAt(i - 1) == b.charAt(j - 1) ? prev
                        : 1 + Math.min(prev, Math.min(dp[j], dp[j - 1]));
                prev = temp;
            }
        }
        return dp[n];
    }

    private int approximateDiff(String a, String b, int cap) {
        // Rough character frequency diff for very large bodies
        int diff = Math.abs(a.length() - b.length());
        return Math.min(diff, cap);
    }
}
