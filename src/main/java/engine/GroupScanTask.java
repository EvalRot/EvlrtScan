package engine;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import engine.EncodingDetector.Encoding;
import template.ScanTemplate;

import java.util.*;

/**
 * A scan task that holds an entire payload group (p1, p2, ... pN).
 * All payloads are sent sequentially for each insertion point,
 * responses collected into a map, and then the differential
 * detection expression is evaluated against the full set.
 */
public class GroupScanTask extends ScanTask {

    private final List<ScanTemplate.PayloadGroupEntry> group;
    private final Map<String, HttpRequestResponse> responses = new LinkedHashMap<>();

    public GroupScanTask(ScanJob parentJob, ScanTemplate template, InsertionPoint insertionPoint,
            List<ScanTemplate.PayloadGroupEntry> group,
            HttpRequest originalRequest, HttpRequestResponse baselineResponse) {
        this(parentJob, template, insertionPoint, group, originalRequest, baselineResponse, null);
    }

    public GroupScanTask(ScanJob parentJob, ScanTemplate template, InsertionPoint insertionPoint,
            List<ScanTemplate.PayloadGroupEntry> group,
            HttpRequest originalRequest, HttpRequestResponse baselineResponse,
            Encoding forcedEncoding) {
        // Use the first payload as the "display" payload
        super(parentJob, template, insertionPoint,
                group.stream().map(e -> e.getId() + ":" + e.getValue())
                        .reduce((a, b) -> a + ", " + b).orElse(""),
                originalRequest, baselineResponse, forcedEncoding);
        this.group = group;
    }

    public List<ScanTemplate.PayloadGroupEntry> getGroup() {
        return group;
    }

    public void putResponse(String payloadId, HttpRequestResponse response) {
        responses.put(payloadId, response);
    }

    public Map<String, HttpRequestResponse> getResponses() {
        return responses;
    }

    /**
     * Build the full response map including baseline for expression evaluation.
     */
    public Map<String, HttpRequestResponse> buildFullResponseMap() {
        Map<String, HttpRequestResponse> full = new LinkedHashMap<>();
        if (getBaselineResponse() != null) {
            full.put("baseline", getBaselineResponse());
        }
        full.putAll(responses);
        return full;
    }
}
