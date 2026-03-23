package engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;

/**
 * A confirmed vulnerability finding from a completed ScanTask.
 * Stores original request, baseline, and all payload request/responses
 * for display in the Findings tab.
 */
public class ScanFinding {
    private final String templateId;
    private final String templateName;
    private final String severity;
    private final String host;
    private final String route; // normalized route
    private final String paramLabel; // insertion point display label
    private final String payload;
    private final String matchedRule;
    private final String triggerReason;
    private final String diffScores;
    private final long timestamp = System.currentTimeMillis();

    // Original unmodified request
    private final HttpRequest originalRequest;

    // Baseline request/response pair (may be null if baseline=false)
    private final HttpRequestResponse baselineRequestResponse;

    // All payload request/responses keyed by payload id (p1, p2, ...) or "single"
    // Uses LinkedHashMap to preserve insertion order
    private final LinkedHashMap<String, HttpRequestResponse> payloadResponses = new LinkedHashMap<>();

    /**
     * Constructor for simple (non-group) ScanTask findings.
     */
    public ScanFinding(ScanTask task) {
        this.templateId = task.getTemplate().getId();
        this.templateName = task.getTemplate().getName();
        this.severity = task.getTemplate().getSeverity();
        this.paramLabel = task.getInsertionPoint().getDisplayLabel();
        this.payload = task.getPayload();
        this.matchedRule = task.getMatchedRule();
        this.triggerReason = task.getTriggerReason();
        this.diffScores = task.getDiffScores();

        HttpRequest req = task.getOriginalRequest();
        this.host = req.httpService().host();
        this.route = req.method() + " " + req.path();
        this.originalRequest = req;

        this.baselineRequestResponse = task.getBaselineResponse();

        // For simple tasks, store the single modified request/response
        HttpRequestResponse actual = task.getActualResponse();
        if (actual != null) {
            payloadResponses.put("payload", actual);
        }
    }

    /**
     * Constructor for GroupScanTask findings.
     * Captures all payload group responses (p1, p2, p3, etc.).
     */
    public ScanFinding(GroupScanTask task) {
        this.templateId = task.getTemplate().getId();
        this.templateName = task.getTemplate().getName();
        this.severity = task.getTemplate().getSeverity();
        this.paramLabel = task.getInsertionPoint().getDisplayLabel();
        this.payload = task.getPayload(); // group label
        this.matchedRule = task.getMatchedRule();
        this.triggerReason = task.getTriggerReason();
        this.diffScores = task.getDiffScores();

        HttpRequest req = task.getOriginalRequest();
        this.host = req.httpService().host();
        this.route = req.method() + " " + req.path();
        this.originalRequest = req;

        this.baselineRequestResponse = task.getBaselineResponse();

        // Copy all group responses
        payloadResponses.putAll(task.getResponses());
    }

    // ---- Getters -------------------------------------------------------

    public String getTemplateId() {
        return templateId;
    }

    public String getTemplateName() {
        return templateName;
    }

    public String getSeverity() {
        return severity;
    }

    public String getHost() {
        return host;
    }

    public String getRoute() {
        return route;
    }

    public String getParamLabel() {
        return paramLabel;
    }

    public String getPayload() {
        return payload;
    }

    public String getMatchedRule() {
        return matchedRule;
    }

    public String getTriggerReason() {
        return triggerReason;
    }

    public String getDiffScores() {
        return diffScores;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public HttpRequest getOriginalRequest() {
        return originalRequest;
    }

    public HttpRequestResponse getBaselineRequestResponse() {
        return baselineRequestResponse;
    }

    /**
     * All payload request/responses in order.
     * For simple tasks: {"payload" → response}
     * For group tasks: {"p1" → response, "p2" → response, ...}
     */
    public LinkedHashMap<String, HttpRequestResponse> getPayloadResponses() {
        return payloadResponses;
    }

    /**
     * Returns the list of payload IDs for tab display.
     */
    public List<String> getPayloadIds() {
        return new ArrayList<>(payloadResponses.keySet());
    }
}
