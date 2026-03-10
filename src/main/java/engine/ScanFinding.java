package engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Base64;

/**
 * A confirmed vulnerability finding from a completed ScanTask.
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
    private final long timestamp = System.currentTimeMillis();

    // Store as bytes for display in the Findings tab
    private final byte[] modifiedRequestBytes;
    private final byte[] responseBytes;
    private final byte[] originalRequestBytes;

    public ScanFinding(ScanTask task) {
        this.templateId = task.getTemplate().getId();

        this.templateName = task.getTemplate().getName();
        this.severity = task.getTemplate().getSeverity();
        this.paramLabel = task.getInsertionPoint().getDisplayLabel();
        this.payload = task.getPayload();
        this.matchedRule = task.getMatchedRule();

        HttpRequest req = task.getOriginalRequest();
        this.host = req.httpService().host();
        this.route = req.method() + " " + req.path();

        this.originalRequestBytes = req.toByteArray().getBytes();

        HttpRequest modified = task.getModifiedRequest();
        this.modifiedRequestBytes = modified != null ? modified.toByteArray().getBytes() : null;

        HttpRequestResponse resp = task.getActualResponse();
        this.responseBytes = (resp != null && resp.hasResponse())
                ? resp.response().toByteArray().getBytes()
                : null;
    }

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

    public long getTimestamp() {
        return timestamp;
    }

    public byte[] getModifiedRequestBytes() {
        return modifiedRequestBytes;
    }

    public byte[] getResponseBytes() {
        return responseBytes;
    }

    public byte[] getOriginalRequestBytes() {
        return originalRequestBytes;
    }

    public String toBase64ModifiedRequest() {
        return modifiedRequestBytes != null ? Base64.getEncoder().encodeToString(modifiedRequestBytes) : "";
    }

    public String toBase64Response() {
        return responseBytes != null ? Base64.getEncoder().encodeToString(responseBytes) : "";
    }
}
