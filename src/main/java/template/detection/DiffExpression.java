package template.detection;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Map;
import java.util.logging.Logger;

/**
 * Recursive-descent parser and evaluator for differential detection
 * expressions.
 *
 * <p>
 * Expression DSL:
 * 
 * <pre>
 *   expr       = or_expr
 *   or_expr    = and_expr ("OR" and_expr)*
 *   and_expr   = atom ("AND" atom)*
 *   atom       = "(" expr ")" | comparison
 *   comparison = ref ("~" | "!~") ref
 *   ref        = "baseline" | "p" DIGIT+
 * </pre>
 *
 * <p>
 * Operators:
 * <ul>
 * <li>{@code ~} — "similar": body diff ratio &lt; threshold</li>
 * <li>{@code !~} — "differs": body diff ratio &gt;= threshold</li>
 * </ul>
 */
public class DiffExpression {

    private static final Logger log = Logger.getLogger(DiffExpression.class.getName());

    /**
     * Evaluate an expression string against a map of named responses.
     *
     * @param expression the DSL expression, e.g. "(baseline ~ p1) AND (baseline !~
     *                   p2)"
     * @param responses  map of response references: "baseline", "p1", "p2", etc.
     * @param threshold  diff ratio threshold for ~ and !~ operators (0.0 - 1.0)
     * @return true if the expression evaluates to true
     */
    public static boolean evaluate(String expression,
            Map<String, HttpRequestResponse> responses,
            double threshold) {
        Parser parser = new Parser(expression.trim(), responses, threshold);
        boolean result = parser.parseExpr();
        if (parser.pos < parser.tokens.length) {
            log.warning("DiffExpression: unexpected tokens after position " + parser.pos
                    + " in: " + expression);
        }
        return result;
    }

    // ---- Tokenizer -----------------------------------------------------

    private static String[] tokenize(String expr) {
        // Insert spaces around operators and parentheses for easy splitting
        String spaced = expr
                .replace("(", " ( ")
                .replace(")", " ) ")
                .replaceAll("!~", " !~ ")
                .replaceAll("(?<![!])~", " ~ "); // ~ but not !~
        return spaced.trim().split("\\s+");
    }

    // ---- Recursive Descent Parser --------------------------------------

    private static class Parser {
        final String[] tokens;
        final Map<String, HttpRequestResponse> responses;
        final double threshold;
        int pos = 0;

        Parser(String expression, Map<String, HttpRequestResponse> responses, double threshold) {
            this.tokens = tokenize(expression);
            this.responses = responses;
            this.threshold = threshold;
        }

        // expr = or_expr
        boolean parseExpr() {
            return parseOr();
        }

        // or_expr = and_expr ("OR" and_expr)*
        boolean parseOr() {
            boolean result = parseAnd();
            while (pos < tokens.length && tokens[pos].equalsIgnoreCase("OR")) {
                pos++; // consume OR
                boolean right = parseAnd();
                result = result || right;
            }
            return result;
        }

        // and_expr = atom ("AND" atom)*
        boolean parseAnd() {
            boolean result = parseAtom();
            while (pos < tokens.length && tokens[pos].equalsIgnoreCase("AND")) {
                pos++; // consume AND
                boolean right = parseAtom();
                result = result && right;
            }
            return result;
        }

        // atom = "(" expr ")" | comparison
        boolean parseAtom() {
            if (pos < tokens.length && tokens[pos].equals("(")) {
                pos++; // consume (
                boolean result = parseExpr();
                if (pos < tokens.length && tokens[pos].equals(")")) {
                    pos++; // consume )
                }
                return result;
            }
            return parseComparison();
        }

        // comparison = ref ("~" | "!~") ref
        boolean parseComparison() {
            String leftRef = tokens[pos++];
            String operator = tokens[pos++];
            String rightRef = tokens[pos++];

            HttpRequestResponse left = responses.get(leftRef);
            HttpRequestResponse right = responses.get(rightRef);

            if (left == null || right == null) {
                log.warning("DiffExpression: missing response for ref '"
                        + (left == null ? leftRef : rightRef) + "'");
                return false;
            }

            double diffRatio = computeBodyDiffRatio(left, right);

            return switch (operator) {
                case "~" -> diffRatio < threshold; // similar
                case "!~" -> diffRatio >= threshold; // differs
                default -> {
                    log.warning("DiffExpression: unknown operator '" + operator + "'");
                    yield false;
                }
            };
        }
    }

    // ---- Body Diff Computation -----------------------------------------

    /**
     * Compute the diff ratio between two response bodies.
     * Returns 0.0 for identical bodies, 1.0 for completely different.
     */
    static double computeBodyDiffRatio(HttpRequestResponse a, HttpRequestResponse b) {
        if (a == null || !a.hasResponse() || b == null || !b.hasResponse())
            return 1.0;

        String bodyA = a.response().bodyToString();
        String bodyB = b.response().bodyToString();

        if (bodyA.equals(bodyB))
            return 0.0;

        int maxLen = Math.max(bodyA.length(), bodyB.length());
        if (maxLen == 0)
            return 0.0;

        // For large bodies use approximate diff, otherwise Levenshtein
        int dist;
        if (bodyA.length() > 5000 || bodyB.length() > 5000) {
            dist = approximateDiff(bodyA, bodyB);
        } else {
            dist = levenshteinDistance(bodyA, bodyB);
        }

        return (double) dist / maxLen;
    }

    private static int levenshteinDistance(String a, String b) {
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

    private static int approximateDiff(String a, String b) {
        // Line-level comparison for large bodies
        String[] linesA = a.split("\n");
        String[] linesB = b.split("\n");
        int common = 0;
        int total = Math.max(linesA.length, linesB.length);
        int minLines = Math.min(linesA.length, linesB.length);
        for (int i = 0; i < minLines; i++) {
            if (linesA[i].equals(linesB[i]))
                common++;
        }
        int diffLines = total - common;
        // Estimate character diff from line diff
        int avgLineLen = (a.length() + b.length()) / (2 * Math.max(total, 1));
        return diffLines * avgLineLen;
    }
}
