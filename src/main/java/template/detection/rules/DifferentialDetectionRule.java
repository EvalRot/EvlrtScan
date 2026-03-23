package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionRule;
import template.detection.DiffExpression;

import java.util.List;
import java.util.Map;

/**
 * Detection rule for differential/boolean-based scanning.
 * Wraps an expression string, threshold, and variable definitions;
 * actual evaluation happens via DiffExpression against a full response map.
 *
 * <p>
 * For normal single-response detection, this rule always returns false
 * (it requires the extended evaluation path in ScanWorkerPool).
 */
public class DifferentialDetectionRule implements DetectionRule {

    private final String expression;
    private final double threshold;
    private final Map<String, String> vars;

    public DifferentialDetectionRule(String expression, double threshold,
            Map<String, String> vars) {
        this.expression = expression;
        this.threshold = threshold;
        this.vars = vars != null ? vars : Map.of();
    }

    /**
     * Standard single-response evaluation — not applicable for differential.
     * Always returns false; use {@link #matchesDifferential} instead.
     */
    @Override
    public boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload) {
        return false; // differential needs the full response map
    }

    /**
     * Evaluate the expression against the full map of named responses.
     */
    public boolean matchesDifferential(Map<String, HttpRequestResponse> responses, List<String> matchedTriggers) {
        return DiffExpression.evaluate(expression, responses, threshold, vars, matchedTriggers);
    }

    public String getExpression() {
        return expression;
    }

    public double getThreshold() {
        return threshold;
    }
}
