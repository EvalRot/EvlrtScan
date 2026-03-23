package template;

import template.detection.DiffExpression;

import java.util.*;

/**
 * Validates ScanTemplate objects after parsing from YAML.
 * Checks structural correctness, required fields, expression syntax, and bracket balance.
 */
public class TemplateValidator {

    /**
     * Validation result containing all errors found.
     */
    public static class ValidationResult {
        private final List<String> errors = new ArrayList<>();

        public void addError(String error) {
            errors.add(error);
        }

        public boolean isValid() {
            return errors.isEmpty();
        }

        public List<String> getErrors() {
            return Collections.unmodifiableList(errors);
        }

        public String getSummary() {
            return String.join("; ", errors);
        }
    }

    /**
     * Validate a parsed ScanTemplate.
     * Returns a ValidationResult with all found issues.
     */
    public static ValidationResult validate(ScanTemplate template) {
        ValidationResult result = new ValidationResult();

        // --- Required field checks ---
        if (template.getId() == null || template.getId().isBlank()) {
            result.addError("Missing required field: 'id'");
        }

        if (template.getName() == null || template.getName().isBlank()) {
            result.addError("Missing required field: 'name'");
        }

        // --- Payload checks ---
        boolean hasPayloads = template.getPayloads() != null && !template.getPayloads().isEmpty();
        boolean hasPayloadGroup = template.getPayloadGroup() != null && !template.getPayloadGroup().isEmpty();

        if (!hasPayloads && !hasPayloadGroup) {
            result.addError("Template must define either 'payloads' or 'payload_group'");
        }

        // Validate payload_group entries
        if (hasPayloadGroup) {
            Set<String> groupIds = new HashSet<>();
            for (ScanTemplate.PayloadGroupEntry entry : template.getPayloadGroup()) {
                if (entry.getId() == null || entry.getId().isBlank()) {
                    result.addError("payload_group entry missing 'id'");
                } else if (!groupIds.add(entry.getId())) {
                    result.addError("Duplicate payload_group id: '" + entry.getId() + "'");
                }
                if (entry.getValue() == null || entry.getValue().isBlank()) {
                    result.addError("payload_group entry '" + entry.getId() + "' has empty 'value'");
                }
                String jt = entry.getJsonType();
                if (jt != null && !jt.equals("keep") && !jt.equals("object") && !jt.equals("array")) {
                    result.addError("payload_group entry '" + entry.getId()
                            + "' has invalid json_type: '" + jt + "' (expected: keep, object, array)");
                }
            }
        }

        // --- Injection strategy check ---
        if (template.getInjectionStrategy() == null) {
            result.addError("Missing or invalid 'injection_strategy'");
        }

        // --- Detection checks ---
        ScanTemplate.Detection detection = template.getDetection();
        if (detection == null) {
            result.addError("Missing 'detection' section");
            return result;
        }

        String logic = detection.getLogic();
        if (logic != null && !logic.equalsIgnoreCase("AND") && !logic.equalsIgnoreCase("OR")) {
            result.addError("Invalid detection logic: '" + logic + "' (expected: AND or OR)");
        }

        List<ScanTemplate.RuleConfig> rules = detection.getRules();
        if (rules == null || rules.isEmpty()) {
            result.addError("Detection section has no 'rules' defined");
            return result;
        }

        // --- Rule-level validation ---
        Set<String> knownRuleTypes = Set.of(
                "body_contains", "body_regex", "header_regex",
                "status_code_change", "time_based", "differential", "smart_diff");

        for (int i = 0; i < rules.size(); i++) {
            ScanTemplate.RuleConfig rule = rules.get(i);
            String ruleLabel = "Rule #" + (i + 1);

            if (rule.getType() == null || rule.getType().isBlank()) {
                result.addError(ruleLabel + ": missing 'type'");
                continue;
            }

            if (!knownRuleTypes.contains(rule.getType())) {
                result.addError(ruleLabel + ": unknown type '" + rule.getType() + "'");
                continue;
            }

            // Type-specific validation
            switch (rule.getType()) {
                case "body_contains" -> {
                    if (rule.getValues() == null || rule.getValues().isEmpty()) {
                        result.addError(ruleLabel + " (body_contains): missing 'values' list");
                    }
                }
                case "body_regex", "header_regex" -> {
                    if (rule.getPattern() == null || rule.getPattern().isBlank()) {
                        result.addError(ruleLabel + " (" + rule.getType() + "): missing 'pattern'");
                    } else {
                        validateRegex(rule.getPattern(), ruleLabel + " (" + rule.getType() + ")", result);
                    }
                }
                case "time_based" -> {
                    if (rule.getMinMs() <= 0) {
                        result.addError(ruleLabel + " (time_based): 'min_ms' must be > 0");
                    }
                }
                case "differential" -> {
                    if (rule.getExpression() == null || rule.getExpression().isBlank()) {
                        result.addError(ruleLabel + " (differential): missing 'expression'");
                    } else {
                        validateExpression(rule.getExpression(), ruleLabel + " (differential)", result);
                    }
                    if (!hasPayloadGroup) {
                        result.addError(ruleLabel + " (differential): requires 'payload_group' to be defined");
                    }
                }
                case "smart_diff" -> {
                    if (rule.getExpression() == null || rule.getExpression().isBlank()) {
                        result.addError(ruleLabel + " (smart_diff): missing 'expression'");
                    } else {
                        validateExpression(rule.getExpression(), ruleLabel + " (smart_diff)", result);
                    }
                    if (!hasPayloadGroup) {
                        result.addError(ruleLabel + " (smart_diff): requires 'payload_group' to be defined");
                    }
                }
            }

            // Validate expression references match payload_group ids
            if (rule.getExpression() != null && hasPayloadGroup) {
                validateExpressionReferences(rule.getExpression(), template.getPayloadGroup(),
                        ruleLabel, result);
            }
        }

        return result;
    }

    /**
     * Validate bracket balance and basic structure of an expression string.
     */
    private static void validateExpression(String expression, String context, ValidationResult result) {
        if (expression == null || expression.isBlank()) {
            return;
        }

        // Check parentheses balance
        int depth = 0;
        for (int i = 0; i < expression.length(); i++) {
            char c = expression.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth < 0) {
                    result.addError(context + ": unmatched closing ')' at position " + i
                            + " in expression: " + expression.trim());
                    return;
                }
            }
        }
        if (depth > 0) {
            result.addError(context + ": " + depth + " unclosed '(' in expression: " + expression.trim());
        }

        // Tokenize and check basic structure
        try {
            List<String> tokens = DiffExpression.tokenize(expression.trim());
            if (tokens.isEmpty()) {
                result.addError(context + ": expression is empty after tokenization");
                return;
            }

            // Check that AND/OR are not at the start or end
            String first = tokens.get(0).toUpperCase();
            String last = tokens.get(tokens.size() - 1).toUpperCase();
            if (first.equals("AND") || first.equals("OR")) {
                result.addError(context + ": expression starts with logical operator '" + first + "'");
            }
            if (last.equals("AND") || last.equals("OR")) {
                result.addError(context + ": expression ends with logical operator '" + last + "'");
            }

            // Check no consecutive logical operators
            for (int i = 0; i < tokens.size() - 1; i++) {
                String curr = tokens.get(i).toUpperCase();
                String next = tokens.get(i + 1).toUpperCase();
                if ((curr.equals("AND") || curr.equals("OR"))
                        && (next.equals("AND") || next.equals("OR"))) {
                    result.addError(context + ": consecutive logical operators '"
                            + curr + " " + next + "' in expression");
                }
            }
        } catch (Exception e) {
            result.addError(context + ": failed to tokenize expression: " + e.getMessage());
        }
    }

    /**
     * Validate that references in the expression (p1, p2, baseline, etc.)
     * correspond to defined payload_group ids.
     */
    private static void validateExpressionReferences(String expression,
            List<ScanTemplate.PayloadGroupEntry> group, String context, ValidationResult result) {
        Set<String> definedIds = new HashSet<>();
        definedIds.add("baseline");
        for (ScanTemplate.PayloadGroupEntry entry : group) {
            definedIds.add(entry.getId());
        }

        try {
            List<String> tokens = DiffExpression.tokenize(expression.trim());
            for (String token : tokens) {
                // Skip operators, parentheses, keywords, quoted strings, numbers
                if (token.equals("(") || token.equals(")") || token.equals(".match"))
                    continue;
                if (token.equalsIgnoreCase("AND") || token.equalsIgnoreCase("OR"))
                    continue;
                if (token.startsWith("\""))
                    continue;
                if (isOperator(token))
                    continue;
                if (isNumeric(token))
                    continue;

                // Extract the ref part (before the first dot)
                String ref = token.contains(".") ? token.substring(0, token.indexOf('.')) : token;

                if (!definedIds.contains(ref)) {
                    result.addError(context + ": expression references undefined id '" + ref
                            + "'. Defined ids: " + definedIds);
                    return; // One error is enough
                }
            }
        } catch (Exception e) {
            // Tokenization failed — already reported above
        }
    }

    private static void validateRegex(String pattern, String context, ValidationResult result) {
        try {
            java.util.regex.Pattern.compile(pattern);
        } catch (java.util.regex.PatternSyntaxException e) {
            result.addError(context + ": invalid regex pattern '" + pattern + "': " + e.getDescription());
        }
    }

    private static boolean isOperator(String token) {
        return Set.of("~", "!~", "==", "!=", "<", ">", "<=", ">=").contains(token);
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
