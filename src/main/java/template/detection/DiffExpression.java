package template.detection;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.*;
import java.util.logging.Logger;

/**
 * Recursive-descent parser and evaluator for differential detection
 * expressions.
 *
 * <p>
 * Extended DSL (backward-compatible with original syntax):
 * 
 * <pre>
 *   expr       = or_expr
 *   or_expr    = and_expr ("OR" and_expr)*
 *   and_expr   = atom ("AND" atom)*
 *   atom       = "(" expr ")" | comparison
 *   comparison = operand operator operand
 *   operand    = ref_prop | number | quoted_string
 *   ref_prop   = ref ("." property)?
 *   ref        = "baseline" | identifier (e.g. "p1", "p2")
 *   property   = "body" | "status" | var_name (resolved via vars to header)
 *
 *   Operators:
 *     ~   — body similar  (diff ratio &lt; threshold)
 *     !~  — body differs  (diff ratio &gt;= threshold)
 *     ==  — equal  (string or numeric)
 *     !=  — not equal
 *     &lt;   — less than      (numeric)
 *     &gt;   — greater than   (numeric)
 *     &lt;=  — less or equal  (numeric)
 *     &gt;=  — greater or equal (numeric)
 * </pre>
 *
 * <p>
 * Bare refs without property (e.g. {@code baseline ~ p1}) default to
 * body comparison, preserving backward compatibility.
 */
public class DiffExpression {

    private static final Logger log = Logger.getLogger(DiffExpression.class.getName());

    // ---- Operand representation ----------------------------------------

    public enum OperandType {
        BODY_REF, STATUS_REF, HEADER_REF, NUMBER, STRING
    }

    public record Operand(OperandType type, String ref, String headerName,
            double numValue, String strValue) {
        public static Operand bodyRef(String ref) {
            return new Operand(OperandType.BODY_REF, ref, null, 0, null);
        }

        public static Operand statusRef(String ref) {
            return new Operand(OperandType.STATUS_REF, ref, null, 0, null);
        }

        public static Operand headerRef(String ref, String header) {
            return new Operand(OperandType.HEADER_REF, ref, header, 0, null);
        }

        public static Operand number(double v) {
            return new Operand(OperandType.NUMBER, null, null, v, null);
        }

        public static Operand string(String v) {
            return new Operand(OperandType.STRING, null, null, 0, v);
        }
    }

    // ---- Public API ----------------------------------------------------

    /**
     * Evaluate an expression against named responses.
     *
     * @param expression DSL expression string
     * @param responses  map of refs ("baseline", "p1", "p2") → responses
     * @param threshold  diff ratio threshold for ~ and !~ operators
     * @param vars       variable definitions (e.g. "h1" → "Content-Length")
     */
    public static boolean evaluate(String expression,
            Map<String, HttpRequestResponse> responses,
            double threshold,
            Map<String, String> vars,
            List<String> matchedTriggers) {
        List<String> tokens = tokenize(expression.trim());
        Parser parser = new Parser(tokens, responses, threshold,
                vars != null ? vars : Collections.emptyMap(),
                matchedTriggers);
        boolean result = parser.parseExpr();
        if (parser.pos < tokens.size()) {
            log.warning("DiffExpression: unexpected tokens after position " + parser.pos
                    + " in: " + expression);
        }
        return result;
    }

    /** Backward-compatible overload. */
    public static boolean evaluate(String expression,
            Map<String, HttpRequestResponse> responses,
            double threshold,
            Map<String, String> vars) {
        return evaluate(expression, responses, threshold, vars, null);
    }
    public static boolean evaluate(String expression,
            Map<String, HttpRequestResponse> responses,
            double threshold) {
        return evaluate(expression, responses, threshold, null);
    }

    // ---- Tokenizer -----------------------------------------------------

    public static List<String> tokenize(String expr) {
        List<String> tokens = new ArrayList<>();
        int i = 0;
        int len = expr.length();
        while (i < len) {
            char c = expr.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
                continue;
            }

            // Parentheses
            if (c == '(' || c == ')') {
                tokens.add(String.valueOf(c));
                i++;
                continue;
            }

            // Quoted string literal
            if (c == '"') {
                int end = expr.indexOf('"', i + 1);
                if (end == -1)
                    end = len;
                tokens.add(expr.substring(i, Math.min(end + 1, len)));
                i = Math.min(end + 1, len);
                continue;
            }

            // Two-character operators: !~ != == <= >=
            if (i + 1 < len) {
                String two = expr.substring(i, i + 2);
                if ("!~".equals(two) || "!=".equals(two) || "==".equals(two)
                        || "<=".equals(two) || ">=".equals(two)) {
                    tokens.add(two);
                    i += 2;
                    continue;
                }
            }

            // Single-character operators: ~ < >
            if (c == '~' || c == '<' || c == '>') {
                tokens.add(String.valueOf(c));
                i++;
                continue;
            }

            // Pseudo-method operator: .match
            if (expr.startsWith(".match", i)) {
                tokens.add(".match");
                i += 6;
                continue;
            }

            // Words: identifiers, numbers, dotted refs (p1.status, baseline.body)
            StringBuilder sb = new StringBuilder();
            while (i < len) {
                char ch = expr.charAt(i);
                if (Character.isLetterOrDigit(ch) || ch == '.' || ch == '_' || ch == '-') {
                    sb.append(ch);
                    i++;
                } else {
                    break;
                }
            }
            if (!sb.isEmpty())
                tokens.add(sb.toString());
        }
        return tokens;
    }

    // ---- Recursive-descent parser --------------------------------------

    public static class Parser {
        final List<String> tokens;
        final Map<String, HttpRequestResponse> responses;
        final double threshold;
        final Map<String, String> vars;
        final List<String> matchedTriggers;
        int pos = 0;

        public Parser(List<String> tokens, Map<String, HttpRequestResponse> responses,
                double threshold, Map<String, String> vars) {
            this(tokens, responses, threshold, vars, null);
        }

        public Parser(List<String> tokens, Map<String, HttpRequestResponse> responses,
                double threshold, Map<String, String> vars, List<String> matchedTriggers) {
            this.tokens = tokens;
            this.responses = responses;
            this.threshold = threshold;
            this.vars = vars;
            this.matchedTriggers = matchedTriggers;
        }

        boolean parseExpr() {
            return parseOr();
        }

        boolean parseOr() {
            int start = pos;
            boolean result = parseAnd();
            if (result && matchedTriggers != null) {
                // Record the tokens that evaluated to true in this OR branch
                matchedTriggers.add(String.join(" ", tokens.subList(start, pos)));
            }

            while (has() && peek().equalsIgnoreCase("OR")) {
                advance(); // consume OR
                start = pos;
                boolean right = parseAnd();
                if (right && matchedTriggers != null) {
                    matchedTriggers.add(String.join(" ", tokens.subList(start, pos)));
                }
                result = result || right;
            }
            return result;
        }

        boolean parseAnd() {
            boolean result = parseAtom();
            while (has() && peek().equalsIgnoreCase("AND")) {
                advance();
                boolean right = parseAtom();
                result = result && right;
            }
            return result;
        }

        boolean parseAtom() {
            if (has() && peek().equals("(")) {
                advance();
                boolean result = parseExpr();
                if (has() && peek().equals(")"))
                    advance();
                return result;
            }

            // Peek ahead: if the second token is ".match" then this is a match operator
            if (pos + 1 < tokens.size() && tokens.get(pos + 1).equals(".match")) {
                Operand left = parseOperand();
                advance(); // consume ".match"
                if (has() && peek().equals("("))
                    advance();
                Operand right = parseOperand();
                if (has() && peek().equals(")"))
                    advance();
                return evalMatch(left, right);
            }

            return parseComparison();
        }

        boolean parseComparison() {
            Operand left = parseOperand();
            String op = advance();
            Operand right = parseOperand();
            return evalComparison(left, op, right);
        }

        Operand parseOperand() {
            String token = advance();

            // Quoted string: "..."
            if (token.startsWith("\"") && token.endsWith("\"") && token.length() >= 2) {
                return Operand.string(token.substring(1, token.length() - 1));
            }

            // Number literal (200, 3.14)
            if (isNumeric(token)) {
                return Operand.number(Double.parseDouble(token));
            }

            // Reference with property: p1.status, baseline.body, p1.h1
            if (token.contains(".")) {
                int dot = token.indexOf('.');
                String ref = token.substring(0, dot);
                String prop = token.substring(dot + 1);
                return switch (prop) {
                    case "body" -> Operand.bodyRef(ref);
                    case "status" -> Operand.statusRef(ref);
                    default -> Operand.headerRef(ref, vars.getOrDefault(prop, prop));
                };
            }

            // Bare reference → defaults to body
            return Operand.bodyRef(token);
        }

        // ---- Evaluation ------------------------------------------------

        public boolean evalComparison(Operand left, String op, Operand right) {
            return switch (op) {
                case "~", "!~" -> evalSimilarity(left, op, right);
                case "==", "!=" -> evalEquality(left, op, right);
                case "<", ">", "<=", ">=" -> evalRelational(left, op, right);
                default -> {
                    log.warning("DiffExpression: unknown operator '" + op + "'");
                    yield false;
                }
            };
        }

        boolean evalSimilarity(Operand left, String op, Operand right) {
            String lRef = bodyRef(left);
            String rRef = bodyRef(right);
            if (lRef == null || rRef == null) {
                log.warning("DiffExpression: ~ / !~ require body references on both sides");
                return false;
            }
            HttpRequestResponse l = responses.get(lRef);
            HttpRequestResponse r = responses.get(rRef);
            if (l == null || r == null) {
                log.warning("DiffExpression: missing response for '"
                        + (l == null ? lRef : rRef) + "'");
                return false;
            }
            double diff = computeBodyDiffRatio(l, r);
            return "~".equals(op) ? diff < threshold : diff >= threshold;
        }

        boolean evalEquality(Operand left, String op, Operand right) {
            String ls = resolveString(left);
            String rs = resolveString(right);
            if (ls == null || rs == null)
                return "!=".equals(op);
            boolean eq = ls.equals(rs);
            return "==".equals(op) ? eq : !eq;
        }

        boolean evalRelational(Operand left, String op, Operand right) {
            Double ln = resolveNumber(left);
            Double rn = resolveNumber(right);
            if (ln == null || rn == null) {
                log.warning("DiffExpression: relational op requires numeric values");
                return false;
            }
            return switch (op) {
                case "<" -> ln < rn;
                case ">" -> ln > rn;
                case "<=" -> ln <= rn;
                case ">=" -> ln >= rn;
                default -> false;
            };
        }

        public boolean evalMatch(Operand targetArg, Operand regexArg) {
            String body = resolveString(targetArg);
            if (body == null) {
                log.warning("DiffExpression: .match() target could not be resolved");
                return false;
            }
            if (regexArg.type() != OperandType.STRING) {
                log.warning("DiffExpression: .match() requires a string regex argument");
                return false;
            }
            String regex = regexArg.strValue();
            try {
                java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                        regex, java.util.regex.Pattern.DOTALL | java.util.regex.Pattern.CASE_INSENSITIVE);
                return p.matcher(body).find();
            } catch (Exception e) {
                log.warning("DiffExpression: invalid regex '" + regex + "' in .match() - " + e.getMessage());
                return false;
            }
        }

        // ---- Resolution helpers ----------------------------------------

        private String bodyRef(Operand o) {
            return o.type() == OperandType.BODY_REF ? o.ref() : null;
        }

        private String resolveString(Operand o) {
            return switch (o.type()) {
                case STRING -> o.strValue();
                case NUMBER -> String.valueOf((int) o.numValue());
                case BODY_REF -> {
                    var r = responses.get(o.ref());
                    yield r != null && r.hasResponse() ? r.response().bodyToString() : null;
                }
                case STATUS_REF -> {
                    var r = responses.get(o.ref());
                    yield r != null && r.hasResponse()
                            ? String.valueOf(r.response().statusCode())
                            : null;
                }
                case HEADER_REF -> {
                    var r = responses.get(o.ref());
                    yield r != null && r.hasResponse()
                            ? r.response().headerValue(o.headerName())
                            : null;
                }
            };
        }

        private Double resolveNumber(Operand o) {
            return switch (o.type()) {
                case NUMBER -> o.numValue();
                case STATUS_REF -> {
                    var r = responses.get(o.ref());
                    yield r != null && r.hasResponse()
                            ? (double) r.response().statusCode()
                            : null;
                }
                case HEADER_REF -> {
                    var r = responses.get(o.ref());
                    if (r == null || !r.hasResponse())
                        yield null;
                    String v = r.response().headerValue(o.headerName());
                    if (v == null)
                        yield null;
                    try {
                        yield Double.parseDouble(v.trim());
                    } catch (NumberFormatException e) {
                        yield null;
                    }
                }
                case STRING -> {
                    try {
                        yield Double.parseDouble(o.strValue());
                    } catch (NumberFormatException e) {
                        yield null;
                    }
                }
                case BODY_REF -> null;
            };
        }

        // ---- Token helpers ---------------------------------------------

        private boolean has() {
            return pos < tokens.size();
        }

        private String peek() {
            return tokens.get(pos);
        }

        private String advance() {
            return tokens.get(pos++);
        }

        private static boolean isNumeric(String s) {
            if (s.isEmpty())
                return false;
            boolean hasDot = false;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '.') {
                    if (hasDot)
                        return false;
                    hasDot = true;
                } else if (!Character.isDigit(c))
                    return false;
            }
            return true;
        }
    }

    // ---- Body Diff Computation (unchanged) -----------------------------

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
        int avgLineLen = (a.length() + b.length()) / (2 * Math.max(total, 1));
        return diffLines * avgLineLen;
    }
}
