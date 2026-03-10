package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionRule;

/**
 * Fires when the payload is literally reflected in the response body (e.g., XSS
 * probe).
 */
public class PayloadReflectedRule implements DetectionRule {

    @Override
    public boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload) {
        if (actual == null || !actual.hasResponse() || payload == null || payload.isEmpty())
            return false;
        return actual.response().bodyToString().contains(payload);
    }
}
