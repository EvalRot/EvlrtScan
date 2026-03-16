package coverage;

import engine.ScanFinding;

import java.util.*;


/**
 * Tracks all known endpoints and their scan status for each active yaml
 * template.
 * Thread-safe — updated from proxy listener (may be any thread) and scan
 * workers.
 */
public class EndpointRecord {

    /** Per-template scan record for this endpoint. */
    public static class TemplateScan {
        private final String templateId;
        private volatile String status; // pending, completed, partial, error
        private volatile long timestamp;
        private volatile int payloadsSent;
        private volatile int payloadsTotal;
        private volatile int findings;
        private List<String> scannedParams = new ArrayList<>();

        public TemplateScan(String templateId) {
            this.templateId = templateId;
            this.status = "pending";
        }

        public String getTemplateId() {
            return templateId;
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public void setTimestamp(long timestamp) {
            this.timestamp = timestamp;
        }

        public int getPayloadsSent() {
            return payloadsSent;
        }

        public void setPayloadsSent(int payloadsSent) {
            this.payloadsSent = payloadsSent;
        }

        public int getPayloadsTotal() {
            return payloadsTotal;
        }

        public void setPayloadsTotal(int payloadsTotal) {
            this.payloadsTotal = payloadsTotal;
        }

        public int getFindings() {
            return findings;
        }

        public void setFindings(int findings) {
            this.findings = findings;
        }

        public List<String> getScannedParams() {
            return scannedParams;
        }

        public void setScannedParams(List<String> scannedParams) {
            this.scannedParams = scannedParams;
        }
    }

    private final String host;
    private final String routeKey; // "POST /api/login"
    private final String normalizedPath;
    private volatile String source; // "proxy" | "sitemap"
    private volatile long firstSeen;
    private volatile String sampleMethod;

    // List of all scan entries (allows multiple scans with the same template)
    private final List<TemplateScan> templateScans = Collections.synchronizedList(new ArrayList<>());
    private final List<ScanFinding> findings = Collections.synchronizedList(new ArrayList<>());

    public EndpointRecord(String host, String routeKey, String normalizedPath, String source) {
        this.host = host;
        this.routeKey = routeKey;
        this.normalizedPath = normalizedPath;
        this.source = source;
        this.firstSeen = System.currentTimeMillis();
        this.sampleMethod = routeKey.split(" ")[0];
    }

    /** Overall scan status for this endpoint across all templates. */
    public ScanStatus getScanStatus(Collection<String> activeTemplateIds) {
        if (activeTemplateIds == null || activeTemplateIds.isEmpty()) {
            // If there are no "active" template IDs to check against,
            // just check if ANY completed scan exists
            boolean hasAny = templateScans.stream()
                    .anyMatch(ts -> "completed".equals(ts.getStatus()));
            return hasAny ? ScanStatus.FULL : ScanStatus.NOT_SCANNED;
        }
        // Check how many of the active template IDs have at least one completed scan
        long completed = activeTemplateIds.stream()
                .filter(id -> templateScans.stream()
                        .anyMatch(ts -> ts.getTemplateId().equals(id) && "completed".equals(ts.getStatus())))
                .count();
        if (completed == 0)
            return ScanStatus.NOT_SCANNED;
        if (completed == activeTemplateIds.size())
            return ScanStatus.FULL;
        return ScanStatus.PARTIAL;
    }

    public enum ScanStatus {
        NOT_SCANNED, PARTIAL, FULL
    }

    public void recordScanStart(String templateId, int payloadsTotal) {
        TemplateScan ts = new TemplateScan(templateId);
        ts.setStatus("partial");
        ts.setPayloadsTotal(payloadsTotal);
        ts.setTimestamp(System.currentTimeMillis());
        templateScans.add(ts);
    }

    public void recordScanComplete(String templateId, int payloadsSent, int findingCount) {
        recordScanComplete(templateId, payloadsSent, findingCount, List.of());
    }

    public void recordScanComplete(String templateId, int payloadsSent, int findingCount, List<String> params) {
        TemplateScan ts = new TemplateScan(templateId);
        ts.setStatus("completed");
        ts.setPayloadsSent(payloadsSent);
        ts.setFindings(findingCount);
        ts.setTimestamp(System.currentTimeMillis());
        ts.setScannedParams(params != null ? params : List.of());
        templateScans.add(ts);
    }

    public void addFinding(ScanFinding finding) {
        findings.add(finding);
    }

    // ---- Getters -------------------------------------------------------
    public String getHost() {
        return host;
    }

    public String getRouteKey() {
        return routeKey;
    }

    public String getNormalizedPath() {
        return normalizedPath;
    }

    public String getSource() {
        return source;
    }

    public long getFirstSeen() {
        return firstSeen;
    }

    public String getSampleMethod() {
        return sampleMethod;
    }

    public List<TemplateScan> getTemplateScans() {
        return Collections.unmodifiableList(templateScans);
    }

    public List<ScanFinding> getFindings() {
        return Collections.unmodifiableList(findings);
    }

    public int getTotalFindingCount() {
        return findings.size();
    }
}
