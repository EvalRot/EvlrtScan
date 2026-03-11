package template;

import java.util.List;

/**
 * Represents a loaded YAML scan template.
 * Templates define payloads and detection logic only.
 * WHERE to inject is chosen by the user in the Scan Dialog.
 */
public class ScanTemplate {

    public enum InjectionStrategy {
        APPEND, // originalValue + payload → "admin" → "admin'"
        REPLACE, // payload only → "admin" → "'"
        INSERT // payload + originalValue → "admin" → "'admin"
    }

    private String id;
    private String name;
    private String category;
    private String severity;
    private List<String> tags;
    private String author;
    private String description;
    private InjectionStrategy injectionStrategy = InjectionStrategy.APPEND;
    private List<String> payloads;
    private List<PayloadGroupEntry> payloadGroup;
    private Detection detection;

    // ---- Nested classes ------------------------------------------------

    public static class Detection {
        private String logic = "OR"; // OR | AND
        private boolean baseline = true;
        private List<RuleConfig> rules;

        public String getLogic() {
            return logic;
        }

        public void setLogic(String logic) {
            this.logic = logic;
        }

        public boolean isBaseline() {
            return baseline;
        }

        public void setBaseline(boolean baseline) {
            this.baseline = baseline;
        }

        public List<RuleConfig> getRules() {
            return rules;
        }

        public void setRules(List<RuleConfig> rules) {
            this.rules = rules;
        }
    }

    public static class PayloadGroupEntry {
        private String id; // "p1", "p2", ...
        private String value; // actual payload string

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

    public static class RuleConfig {
        private String type;
        // body_contains
        private List<String> values;
        private Boolean caseSensitive;
        // status_code_change / status_code_in
        private List<Integer> to;
        // response_time
        private Integer minMs;
        // body_diff / content_length_diff
        private Double threshold;
        // header_contains
        private String header;
        // body_regex
        private String pattern;
        // differential
        private String expression;
        // smart_diff
        private Double contentThreshold;
        private Double structureThreshold;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public List<String> getValues() {
            return values;
        }

        public void setValues(List<String> values) {
            this.values = values;
        }

        public Boolean getCaseSensitive() {
            return caseSensitive;
        }

        public void setCaseSensitive(Boolean caseSensitive) {
            this.caseSensitive = caseSensitive;
        }

        public List<Integer> getTo() {
            return to;
        }

        public void setTo(List<Integer> to) {
            this.to = to;
        }

        public Integer getMinMs() {
            return minMs;
        }

        public void setMinMs(Integer minMs) {
            this.minMs = minMs;
        }

        public Double getThreshold() {
            return threshold;
        }

        public void setThreshold(Double threshold) {
            this.threshold = threshold;
        }

        public String getHeader() {
            return header;
        }

        public void setHeader(String header) {
            this.header = header;
        }

        public String getPattern() {
            return pattern;
        }

        public void setPattern(String pattern) {
            this.pattern = pattern;
        }

        public String getExpression() {
            return expression;
        }

        public void setExpression(String expression) {
            this.expression = expression;
        }

        public Double getContentThreshold() {
            return contentThreshold;
        }

        public void setContentThreshold(Double contentThreshold) {
            this.contentThreshold = contentThreshold;
        }

        public Double getStructureThreshold() {
            return structureThreshold;
        }

        public void setStructureThreshold(Double structureThreshold) {
            this.structureThreshold = structureThreshold;
        }
    }

    // ---- Getters / Setters ---------------------------------------------

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public List<String> getTags() {
        return tags;
    }

    public void setTags(List<String> tags) {
        this.tags = tags;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public InjectionStrategy getInjectionStrategy() {
        return injectionStrategy;
    }

    public void setInjectionStrategy(InjectionStrategy injectionStrategy) {
        this.injectionStrategy = injectionStrategy;
    }

    public List<String> getPayloads() {
        return payloads;
    }

    public void setPayloads(List<String> payloads) {
        this.payloads = payloads;
    }

    public List<PayloadGroupEntry> getPayloadGroup() {
        return payloadGroup;
    }

    public void setPayloadGroup(List<PayloadGroupEntry> payloadGroup) {
        this.payloadGroup = payloadGroup;
    }

    public Detection getDetection() {
        return detection;
    }

    public void setDetection(Detection detection) {
        this.detection = detection;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s", severity, name);
    }
}
