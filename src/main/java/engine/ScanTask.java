package engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import engine.EncodingDetector.Encoding;
import template.ScanTemplate;

/**
 * Atomic unit of scan work:
 * one payload × one insertion point × one template.
 * Optionally carries a forcedEncoding for encoding-aware injection
 * (e.g. UNICODE for JSON auto-retry).
 */
public class ScanTask {
    public enum Status {
        PENDING, RUNNING, HIT, MISS, ERROR, TIMEOUT, CANCELLED
    }

    private final ScanJob parentJob;
    private final ScanTemplate template;
    private final InsertionPoint insertionPoint;
    private final String payload;
    private final HttpRequest originalRequest;
    private final HttpRequestResponse baselineResponse;
    private final Encoding forcedEncoding; // null = auto-detect

    // Set during execution
    private volatile Status status = Status.PENDING;
    private HttpRequest modifiedRequest;
    private HttpRequestResponse actualResponse;
    private long elapsedMs;
    private String matchedRule;
    private String errorMessage;
    private String jsonType = "keep"; // keep | object | array

    public ScanTask(ScanJob parentJob, ScanTemplate template, InsertionPoint insertionPoint,
            String payload, HttpRequest originalRequest, HttpRequestResponse baselineResponse) {
        this(parentJob, template, insertionPoint, payload, originalRequest, baselineResponse, null);
    }

    public ScanTask(ScanJob parentJob, ScanTemplate template, InsertionPoint insertionPoint,
            String payload, HttpRequest originalRequest, HttpRequestResponse baselineResponse,
            Encoding forcedEncoding) {
        this.parentJob = parentJob;
        this.template = template;
        this.insertionPoint = insertionPoint;
        this.payload = payload;
        this.originalRequest = originalRequest;
        this.baselineResponse = baselineResponse;
        this.forcedEncoding = forcedEncoding;
    }

    // ---- Getters -------------------------------------------------------
    public ScanJob getParentJob() {
        return parentJob;
    }

    public ScanTemplate getTemplate() {
        return template;
    }

    public InsertionPoint getInsertionPoint() {
        return insertionPoint;
    }

    public String getPayload() {
        return payload;
    }

    public HttpRequest getOriginalRequest() {
        return originalRequest;
    }

    public HttpRequestResponse getBaselineResponse() {
        return baselineResponse;
    }

    public Encoding getForcedEncoding() {
        return forcedEncoding;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public HttpRequest getModifiedRequest() {
        return modifiedRequest;
    }

    public void setModifiedRequest(HttpRequest modifiedRequest) {
        this.modifiedRequest = modifiedRequest;
    }

    public HttpRequestResponse getActualResponse() {
        return actualResponse;
    }

    public void setActualResponse(HttpRequestResponse actualResponse) {
        this.actualResponse = actualResponse;
    }

    public long getElapsedMs() {
        return elapsedMs;
    }

    public void setElapsedMs(long elapsedMs) {
        this.elapsedMs = elapsedMs;
    }

    public String getMatchedRule() {
        return matchedRule;
    }

    public void setMatchedRule(String matchedRule) {
        this.matchedRule = matchedRule;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getJsonType() {
        return jsonType;
    }

    public void setJsonType(String jsonType) {
        this.jsonType = jsonType;
    }
}
