package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionRule;
import java.util.List;

/**
 * Fires when the response status code changes compared to baseline, or is in a
 * given list.
 */
public class StatusCodeRule implements DetectionRule {
    private final List<Integer> targetCodes;
    private final boolean compareToBaseline; // true = status_code_change, false = status_code_in

    public StatusCodeRule(List<Integer> targetCodes, boolean compareToBaseline) {
        this.targetCodes = targetCodes;
        this.compareToBaseline = compareToBaseline;
    }

    @Override
    public boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload) {
        if (actual == null || !actual.hasResponse())
            return false;
        int actualCode = actual.response().statusCode();

        if (compareToBaseline) {
            // status_code_change: baseline != actual AND actual is in target list
            if (baseline == null || !baseline.hasResponse())
                return false;
            int baseCode = baseline.response().statusCode();
            return baseCode != actualCode && targetCodes.contains(actualCode);
        } else {
            // status_code_in: actual must be in list
            return targetCodes.contains(actualCode);
        }
    }
}
