package template.detection;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * A single detection rule that checks whether a response indicates a
 * vulnerability.
 */
public interface DetectionRule {
    /**
     * @param baseline The original request/response (may be null if baseline
     *                 disabled)
     * @param actual   The response after injecting the payload
     * @param payload  The payload that was injected
     * @return true if this rule considers the response a match (potential hit)
     */
    boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload);
}
