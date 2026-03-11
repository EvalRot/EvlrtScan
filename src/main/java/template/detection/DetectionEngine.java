package template.detection;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.ScanTemplate;
import template.detection.rules.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates a set of detection rules against a response and returns whether the
 * template matched.
 */
public class DetectionEngine {

    /**
     * Build rule instances from the template's rule configs.
     */
    public static List<DetectionRule> buildRules(ScanTemplate.Detection detection) {
        List<DetectionRule> rules = new ArrayList<>();
        if (detection == null || detection.getRules() == null)
            return rules;

        for (ScanTemplate.RuleConfig cfg : detection.getRules()) {
            DetectionRule rule = switch (cfg.getType()) {
                case "body_contains" -> new BodyContainsRule(cfg.getValues(), cfg.getCaseSensitive());
                case "status_code_change" -> new StatusCodeRule(cfg.getTo(), true);
                case "status_code_in" -> new StatusCodeRule(cfg.getTo(), false);
                case "response_time" -> new ResponseTimeRule(cfg.getMinMs() != null ? cfg.getMinMs() : 5000);
                case "payload_reflected" -> new PayloadReflectedRule();
                case "body_diff" -> new BodyDiffRule(cfg.getThreshold() != null ? cfg.getThreshold() : 0.3);
                case "header_contains" -> new HeaderContainsRule(cfg.getHeader(), cfg.getValues());
                case "body_regex" -> new BodyRegexRule(cfg.getPattern());
                case "differential" -> new DifferentialDetectionRule(
                        cfg.getExpression(), cfg.getThreshold() != null ? cfg.getThreshold() : 0.1);
                case "smart_diff" -> new SmartDiffDetectionRule(
                        cfg.getExpression(),
                        cfg.getContentThreshold() != null ? cfg.getContentThreshold() : 0.90,
                        cfg.getStructureThreshold() != null ? cfg.getStructureThreshold() : 0.95);
                default -> null;
            };
            if (rule != null)
                rules.add(rule);
        }
        return rules;
    }

    /**
     * Returns true if the detection condition is met (OR or AND logic over rules).
     */
    public static boolean evaluate(ScanTemplate.Detection detection,
            List<DetectionRule> rules,
            HttpRequestResponse baseline,
            HttpRequestResponse actual,
            String payload) {
        if (rules.isEmpty())
            return false;
        boolean isAnd = "AND".equalsIgnoreCase(detection.getLogic());

        for (DetectionRule rule : rules) {
            boolean match = rule.matches(baseline, actual, payload);
            if (isAnd && !match)
                return false;
            if (!isAnd && match)
                return true;
        }
        return isAnd; // AND: all passed → true; OR: none passed → false
    }
}
