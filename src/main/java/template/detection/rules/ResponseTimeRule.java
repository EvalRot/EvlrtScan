package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionRule;

/**
 * Fires when the response time exceeds the configured threshold (time-based
 * blind).
 * Uses Montoya's built-in TimingData API.
 */
public class ResponseTimeRule implements DetectionRule {
    private final long minMs;

    public ResponseTimeRule(int minMs) {
        this.minMs = minMs;
    }

    @Override
    public boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload) {
        if (actual == null || !actual.hasResponse())
            return false;

        var timingOpt = actual.timingData();
        if (timingOpt.isEmpty())
            return false;

        long elapsed = timingOpt.get().timeBetweenRequestSentAndEndOfResponse().toMillis();
        return elapsed >= minMs;
    }
}
