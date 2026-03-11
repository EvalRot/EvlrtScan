package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionRule;
import template.detection.smartdiff.SmartDiffResult;

import java.util.Map;

/**
 * Detection rule for smart differential analysis.
 * Uses SmartDiffEngine to compare responses while ignoring
 * dynamic elements and reflected input.
 *
 * <p>
 * Like DifferentialDetectionRule, this requires the group execution
 * path — standard single-response evaluation always returns false.
 */
public class SmartDiffDetectionRule implements DetectionRule {

    private final String expression;
    private final double contentThreshold;
    private final double structureThreshold;

    public SmartDiffDetectionRule(String expression,
            double contentThreshold, double structureThreshold) {
        this.expression = expression;
        this.contentThreshold = contentThreshold;
        this.structureThreshold = structureThreshold;
    }

    /**
     * Standard single-response evaluation — not applicable for smart diff.
     * Always returns false; use {@link #matchesSmart} instead.
     */
    @Override
    public boolean matches(HttpRequestResponse baseline, HttpRequestResponse actual, String payload) {
        return false;
    }

    /**
     * Evaluate the expression against SmartDiff results.
     *
     * @param results map of comparison pair key → SmartDiffResult
     *                (e.g. "baseline~p1" → result, "baseline~p2" → result)
     */
    public boolean matchesSmart(Map<String, SmartDiffResult> results) {
        return SmartDiffExpressionEvaluator.evaluate(
                expression, results, contentThreshold, structureThreshold);
    }

    public String getExpression() {
        return expression;
    }

    public double getContentThreshold() {
        return contentThreshold;
    }

    public double getStructureThreshold() {
        return structureThreshold;
    }

    // ---- Inner expression evaluator using the same DSL as DiffExpression ----

    /**
     * Evaluates expressions like "(baseline ~ p1) AND (baseline !~ p2)"
     * using SmartDiffResult instead of raw body comparison.
     */
    static class SmartDiffExpressionEvaluator {

        static boolean evaluate(String expression, Map<String, SmartDiffResult> results,
                double contentThreshold, double structureThreshold) {
            String[] tokens = tokenize(expression.trim());
            int[] pos = { 0 };
            return parseOr(tokens, pos, results, contentThreshold, structureThreshold);
        }

        private static String[] tokenize(String expr) {
            String spaced = expr
                    .replace("(", " ( ")
                    .replace(")", " ) ")
                    .replaceAll("!~", " !~ ")
                    .replaceAll("(?<![!])~", " ~ ");
            return spaced.trim().split("\\s+");
        }

        private static boolean parseOr(String[] tokens, int[] pos,
                Map<String, SmartDiffResult> results,
                double ct, double st) {
            boolean result = parseAnd(tokens, pos, results, ct, st);
            while (pos[0] < tokens.length && tokens[pos[0]].equalsIgnoreCase("OR")) {
                pos[0]++;
                boolean right = parseAnd(tokens, pos, results, ct, st);
                result = result || right;
            }
            return result;
        }

        private static boolean parseAnd(String[] tokens, int[] pos,
                Map<String, SmartDiffResult> results,
                double ct, double st) {
            boolean result = parseAtom(tokens, pos, results, ct, st);
            while (pos[0] < tokens.length && tokens[pos[0]].equalsIgnoreCase("AND")) {
                pos[0]++;
                boolean right = parseAtom(tokens, pos, results, ct, st);
                result = result && right;
            }
            return result;
        }

        private static boolean parseAtom(String[] tokens, int[] pos,
                Map<String, SmartDiffResult> results,
                double ct, double st) {
            if (pos[0] < tokens.length && tokens[pos[0]].equals("(")) {
                pos[0]++;
                boolean result = parseOr(tokens, pos, results, ct, st);
                if (pos[0] < tokens.length && tokens[pos[0]].equals(")")) {
                    pos[0]++;
                }
                return result;
            }
            return parseComparison(tokens, pos, results, ct, st);
        }

        private static boolean parseComparison(String[] tokens, int[] pos,
                Map<String, SmartDiffResult> results,
                double ct, double st) {
            String leftRef = tokens[pos[0]++];
            String operator = tokens[pos[0]++];
            String rightRef = tokens[pos[0]++];

            // Build lookup key: "left~right" (sorted alphabetically for consistency)
            String key = leftRef + "~" + rightRef;
            String altKey = rightRef + "~" + leftRef;

            SmartDiffResult result = results.get(key);
            if (result == null)
                result = results.get(altKey);

            if (result == null) {
                return false; // missing comparison data
            }

            return switch (operator) {
                case "~" -> result.isSimilar(ct, st);
                case "!~" -> result.isDifferent(ct, st);
                default -> false;
            };
        }
    }
}
