package template.detection.rules;

import burp.api.montoya.http.message.HttpRequestResponse;
import template.detection.DetectionRule;
import template.detection.DiffExpression;
import template.detection.smartdiff.SmartDiffResult;

import java.util.*;
import java.util.logging.Logger;

/**
 * Detection rule for smart differential analysis.
 * Uses SmartDiffEngine to compare responses while ignoring
 * dynamic elements and reflected input.
 *
 * <p>
 * Like DifferentialDetectionRule, this requires the group execution
 * path — standard single-response evaluation always returns false.
 *
 * <p>
 * The extended evaluator supports property access (p1.status, p1.h1)
 * and comparison operators (==, !=, &lt;, &gt;) in addition to the
 * original ~ / !~ body-similarity operators.
 */
public class SmartDiffDetectionRule implements DetectionRule {

    private static final Logger log = Logger.getLogger(SmartDiffDetectionRule.class.getName());

    private final String expression;
    private final double contentThreshold;
    private final double structureThreshold;
    private final Map<String, String> vars;

    public SmartDiffDetectionRule(String expression,
            double contentThreshold, double structureThreshold,
            Map<String, String> vars) {
        this.expression = expression;
        this.contentThreshold = contentThreshold;
        this.structureThreshold = structureThreshold;
        this.vars = vars != null ? vars : Map.of();
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
     * Evaluate the expression against SmartDiff results and raw responses.
     *
     * @param results   map of comparison pair key → SmartDiffResult
     *                  (e.g. "baseline~p1" → result)
     * @param responses map of individual refs → HttpRequestResponse
     *                  (e.g. "baseline", "p1", "p2")
     */
    public boolean matchesSmart(Map<String, SmartDiffResult> results,
            Map<String, HttpRequestResponse> responses) {
        return SmartDiffExpressionEvaluator.evaluate(
                expression, results, responses,
                contentThreshold, structureThreshold, vars);
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

    // ---- Inner expression evaluator ------------------------------------

    /**
     * Evaluates expressions like "(baseline ~ p1) AND (p1.status != 200)"
     * using SmartDiffResult for body similarity and raw responses for
     * status/header comparisons.
     */
    static class SmartDiffExpressionEvaluator {

        static boolean evaluate(String expression,
                Map<String, SmartDiffResult> results,
                Map<String, HttpRequestResponse> responses,
                double ct, double st,
                Map<String, String> vars) {
            List<String> tokens = DiffExpression.tokenize(expression.trim());
            int[] pos = { 0 };
            return parseOr(tokens, pos, results, responses, ct, st, vars);
        }

        private static boolean parseOr(List<String> tokens, int[] pos,
                Map<String, SmartDiffResult> results,
                Map<String, HttpRequestResponse> responses,
                double ct, double st, Map<String, String> vars) {
            boolean result = parseAnd(tokens, pos, results, responses, ct, st, vars);
            while (pos[0] < tokens.size() && tokens.get(pos[0]).equalsIgnoreCase("OR")) {
                pos[0]++;
                boolean right = parseAnd(tokens, pos, results, responses, ct, st, vars);
                result = result || right;
            }
            return result;
        }

        private static boolean parseAnd(List<String> tokens, int[] pos,
                Map<String, SmartDiffResult> results,
                Map<String, HttpRequestResponse> responses,
                double ct, double st, Map<String, String> vars) {
            boolean result = parseAtom(tokens, pos, results, responses, ct, st, vars);
            while (pos[0] < tokens.size() && tokens.get(pos[0]).equalsIgnoreCase("AND")) {
                pos[0]++;
                boolean right = parseAtom(tokens, pos, results, responses, ct, st, vars);
                result = result && right;
            }
            return result;
        }

        private static boolean parseAtom(List<String> tokens, int[] pos,
                Map<String, SmartDiffResult> results,
                Map<String, HttpRequestResponse> responses,
                double ct, double st, Map<String, String> vars) {
            if (pos[0] < tokens.size() && tokens.get(pos[0]).equals("(")) {
                pos[0]++;
                boolean result = parseOr(tokens, pos, results, responses, ct, st, vars);
                if (pos[0] < tokens.size() && tokens.get(pos[0]).equals(")")) {
                    pos[0]++;
                }
                return result;
            }
            return parseComparison(tokens, pos, results, responses, ct, st, vars);
        }

        private static boolean parseComparison(List<String> tokens, int[] pos,
                Map<String, SmartDiffResult> results,
                Map<String, HttpRequestResponse> responses,
                double ct, double st, Map<String, String> vars) {

            DiffExpression.Operand left = parseOperand(tokens, pos, vars);
            String operator = tokens.get(pos[0]++);
            DiffExpression.Operand right = parseOperand(tokens, pos, vars);

            // For ~ and !~ on body refs, use SmartDiffResult instead of raw diff
            if (("~".equals(operator) || "!~".equals(operator))
                    && left.type() == DiffExpression.OperandType.BODY_REF
                    && right.type() == DiffExpression.OperandType.BODY_REF) {
                return evalSmartSimilarity(left.ref(), right.ref(), operator, results, ct, st);
            }

            // For everything else, delegate to DiffExpression-style evaluation
            // using a temporary Parser backed by the actual responses
            var parser = new DiffExpression.Parser(
                    tokens, responses, 0, vars);
            return parser.evalComparison(left, operator, right);
        }

        private static DiffExpression.Operand parseOperand(
                List<String> tokens, int[] pos, Map<String, String> vars) {
            String token = tokens.get(pos[0]++);

            // Quoted string
            if (token.startsWith("\"") && token.endsWith("\"") && token.length() >= 2) {
                return DiffExpression.Operand.string(token.substring(1, token.length() - 1));
            }

            // Number literal
            if (isNumeric(token)) {
                return DiffExpression.Operand.number(Double.parseDouble(token));
            }

            // Reference with property
            if (token.contains(".")) {
                int dot = token.indexOf('.');
                String ref = token.substring(0, dot);
                String prop = token.substring(dot + 1);
                return switch (prop) {
                    case "body"   -> DiffExpression.Operand.bodyRef(ref);
                    case "status" -> DiffExpression.Operand.statusRef(ref);
                    default       -> DiffExpression.Operand.headerRef(
                            ref, vars.getOrDefault(prop, prop));
                };
            }

            // Bare reference → body
            return DiffExpression.Operand.bodyRef(token);
        }

        private static boolean evalSmartSimilarity(String leftRef, String rightRef,
                String operator,
                Map<String, SmartDiffResult> results,
                double ct, double st) {
            String key = leftRef + "~" + rightRef;
            String altKey = rightRef + "~" + leftRef;
            SmartDiffResult result = results.get(key);
            if (result == null) result = results.get(altKey);

            if (result == null) {
                log.warning("SmartDiffExpression: no comparison data for "
                        + leftRef + " ~ " + rightRef);
                return false;
            }

            return switch (operator) {
                case "~"  -> result.isSimilar(ct, st);
                case "!~" -> result.isDifferent(ct, st);
                default   -> false;
            };
        }

        private static boolean isNumeric(String s) {
            if (s.isEmpty()) return false;
            boolean hasDot = false;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '.') { if (hasDot) return false; hasDot = true; }
                else if (!Character.isDigit(c)) return false;
            }
            return true;
        }
    }
}
