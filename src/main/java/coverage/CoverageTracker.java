package coverage;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import com.google.gson.*;
import engine.ScanJob;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Central store for all known endpoints and their scan coverage.
 * - Backed by Montoya Persistence (survives Burp project reload)
 * - Supports JSON export/import for cross-project data sharing
 */
public class CoverageTracker {
    private static final Logger log = Logger.getLogger(CoverageTracker.class.getName());
    private static final String PERSIST_KEY = "evlrtscan.coverage";

    private final MontoyaApi api;
    private final RouteNormalizer normalizer = new RouteNormalizer();

    // host → routeKey → record
    private final ConcurrentHashMap<String, ConcurrentHashMap<String, EndpointRecord>> data = new ConcurrentHashMap<>();

    // UI listener — called whenever coverage data changes
    private volatile Consumer<Void> changeListener;

    // Debounced persistence writer — avoids hammering disk on every proxy request
    private final ScheduledExecutorService saveScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "evlrtscan-persist");
        t.setDaemon(true);
        return t;
    });
    private volatile ScheduledFuture<?> pendingSave;

    public CoverageTracker(MontoyaApi api) {
        this.api = api;
        loadFromPersistence();
    }

    // ---- Endpoint registration -----------------------------------------

    /**
     * Register an endpoint seen in Proxy / SiteMap. No-op if already known.
     */
    public EndpointRecord register(String host, String method, String path, String source) {
        String routeKey = normalizer.routeKey(method, path);
        String normalizedPath = normalizer.normalize(path);

        var hostMap = data.computeIfAbsent(host, h -> new ConcurrentHashMap<>());
        EndpointRecord record = hostMap.computeIfAbsent(routeKey,
                key -> new EndpointRecord(host, routeKey, normalizedPath, source));

        notifyChange();
        scheduleSave();
        return record;
    }

    public EndpointRecord get(String host, String routeKey) {
        var hostMap = data.get(host);
        return hostMap != null ? hostMap.get(routeKey) : null;
    }

    public Map<String, Map<String, EndpointRecord>> getAll() {
        Map<String, Map<String, EndpointRecord>> result = new LinkedHashMap<>();
        data.forEach((host, routes) -> result.put(host, new LinkedHashMap<>(routes)));
        return result;
    }

    // ---- Scan result recording -----------------------------------------

    /**
     * Called by ScanEngine when a job completes. Records scan results into
     * coverage.
     */
    public void recordJobCompletion(ScanJob job) {
        String host = job.getOriginalRequest().httpService().host();
        String method = job.getOriginalRequest().method();
        String path = job.getOriginalRequest().path();

        EndpointRecord record = register(host, method, path, "scan");

        // Collect scanned parameter names
        List<String> scannedParams = job.getSelectedPoints().stream()
                .map(p -> p.getDisplayLabel())
                .toList();

        job.getTemplates().forEach(template -> {
            // Calculate payloads correctly (flat payloads + group payloads)
            int flatPayloads = template.getPayloads() != null ? template.getPayloads().size() : 0;
            int groupPayloads = template.getPayloadGroup() != null ? template.getPayloadGroup().size() : 0;
            int totalPayloads = (flatPayloads + groupPayloads) * job.getSelectedPoints().size();

            int hits = (int) job.getFindings().stream()
                    .filter(f -> f.getTemplateId().equals(template.getId())).count();

            // Append a new scan entry (unique key = templateId + timestamp)
            record.recordScanComplete(template.getId(), totalPayloads, hits, scannedParams);
        });

        // Add findings
        job.getFindings().forEach(record::addFinding);

        saveToPersistence();
        notifyChange();
    }

    // ---- Persistence ---------------------------------------------------

    private void saveToPersistence() {
        try {
            PersistedObject root = api.persistence().extensionData();
            String json = serialize();
            root.setString(PERSIST_KEY, json);
        } catch (Exception e) {
            log.warning("Failed to save coverage to persistence: " + e.getMessage());
        }
    }

    private void loadFromPersistence() {
        try {
            PersistedObject root = api.persistence().extensionData();
            String json = root.getString(PERSIST_KEY);
            if (json != null && !json.isBlank()) {
                deserializeInto(json, false);
                log.info("Coverage loaded from Burp project: "
                        + data.values().stream().mapToInt(Map::size).sum() + " endpoints");
            }
        } catch (Exception e) {
            log.warning("Failed to load coverage from persistence: " + e.getMessage());
        }
    }

    // ---- JSON Export/Import -------------------------------------------

    public void exportToFile(File file) throws IOException {
        String json = serialize();
        Files.writeString(file.toPath(), json);
        log.info("Coverage exported to: " + file.getAbsolutePath());
    }

    public void importFromFile(File file) throws IOException {
        String json = Files.readString(file.toPath());
        // merge=true: keep newer timestamps
        deserializeInto(json, true);
        saveToPersistence();
        notifyChange();
        log.info("Coverage imported from: " + file.getAbsolutePath());
    }

    private String serialize() {
        JsonObject root = new JsonObject();
        root.addProperty("version", 2);
        root.addProperty("exportedAt", System.currentTimeMillis());

        JsonObject hostsJson = new JsonObject();
        data.forEach((host, routes) -> {
            JsonObject routesJson = new JsonObject();
            routes.forEach((routeKey, record) -> {
                JsonObject recJson = new JsonObject();
                recJson.addProperty("normalizedPath", record.getNormalizedPath());
                recJson.addProperty("source", record.getSource());
                recJson.addProperty("firstSeen", record.getFirstSeen());

                // Serialize scans as an array (supports multiple entries per template)
                JsonArray scansArr = new JsonArray();
                record.getTemplateScans().forEach(ts -> {
                    JsonObject tsJson = new JsonObject();
                    tsJson.addProperty("templateId", ts.getTemplateId());
                    tsJson.addProperty("status", ts.getStatus());
                    tsJson.addProperty("timestamp", ts.getTimestamp());
                    tsJson.addProperty("payloadsSent", ts.getPayloadsSent());
                    tsJson.addProperty("findings", ts.getFindings());
                    if (ts.getScannedParams() != null && !ts.getScannedParams().isEmpty()) {
                        JsonArray paramsArr = new JsonArray();
                        ts.getScannedParams().forEach(paramsArr::add);
                        tsJson.add("scannedParams", paramsArr);
                    }
                    scansArr.add(tsJson);
                });
                recJson.add("scans", scansArr);

                // Serialize findings (summary only, not full request bytes)
                JsonArray findingsArr = new JsonArray();
                record.getFindings().forEach(f -> {
                    JsonObject fj = new JsonObject();
                    fj.addProperty("templateId", f.getTemplateId());
                    fj.addProperty("severity", f.getSeverity());
                    fj.addProperty("param", f.getParamLabel());
                    fj.addProperty("payload", f.getPayload());
                    fj.addProperty("matchedRule", f.getMatchedRule());
                    fj.addProperty("timestamp", f.getTimestamp());
                    // Serialize first payload response for backward compatibility
                    var responses = f.getPayloadResponses();
                    if (!responses.isEmpty()) {
                        var first = responses.values().iterator().next();
                        if (first != null && first.request() != null) {
                            fj.addProperty("requestB64", java.util.Base64.getEncoder()
                                    .encodeToString(first.request().toByteArray().getBytes()));
                        }
                        if (first != null && first.hasResponse()) {
                            fj.addProperty("responseB64", java.util.Base64.getEncoder()
                                    .encodeToString(first.response().toByteArray().getBytes()));
                        }
                    }
                    findingsArr.add(fj);
                });
                recJson.add("findings", findingsArr);

                routesJson.add(routeKey, recJson);
            });
            hostsJson.add(host, routesJson);
        });
        root.add("hosts", hostsJson);
        return new GsonBuilder().setPrettyPrinting().create().toJson(root);
    }

    private void deserializeInto(String json, boolean merge) {
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonObject hostsJson = root.getAsJsonObject("hosts");
            if (hostsJson == null)
                return;

            hostsJson.entrySet().forEach(hostEntry -> {
                String host = hostEntry.getKey();
                JsonObject routesJson = hostEntry.getValue().getAsJsonObject();

                routesJson.entrySet().forEach(routeEntry -> {
                    String routeKey = routeEntry.getKey();
                    JsonObject rec = routeEntry.getValue().getAsJsonObject();

                    String src = rec.has("source") ? rec.get("source").getAsString() : "import";
                    String normalizedPath = rec.has("normalizedPath")
                            ? rec.get("normalizedPath").getAsString()
                            : routeKey;

                    var hostMap = data.computeIfAbsent(host, h -> new ConcurrentHashMap<>());
                    EndpointRecord record = hostMap.computeIfAbsent(routeKey,
                            k -> new EndpointRecord(host, k, normalizedPath, src));

                    // Handle both v1 (JsonObject keyed by templateId) and v2 (JsonArray)
                    JsonElement scansEl = rec.get("scans");
                    if (scansEl != null) {
                        if (scansEl.isJsonArray()) {
                            restoreScansFromArray(record, scansEl.getAsJsonArray());
                        } else if (scansEl.isJsonObject()) {
                            restoreScansFromObject(record, scansEl.getAsJsonObject());
                        }
                    }
                });
            });
        } catch (Exception e) {
            log.warning("Failed to deserialize coverage: " + e.getMessage());
        }
    }

    /** Restore from v2 format (array of scan entries). */
    private void restoreScansFromArray(EndpointRecord record, JsonArray scansArr) {
        for (JsonElement el : scansArr) {
            JsonObject tsJson = el.getAsJsonObject();
            String tid = tsJson.has("templateId") ? tsJson.get("templateId").getAsString() : "";
            int payloads = tsJson.has("payloadsSent") ? tsJson.get("payloadsSent").getAsInt() : 0;
            int findings = tsJson.has("findings") ? tsJson.get("findings").getAsInt() : 0;
            List<String> params = new ArrayList<>();
            if (tsJson.has("scannedParams")) {
                tsJson.getAsJsonArray("scannedParams").forEach(p -> params.add(p.getAsString()));
            }
            record.recordScanComplete(tid, payloads, findings, params);
        }
    }

    /** Restore from v1 format (object keyed by templateId, for backward compat). */
    private void restoreScansFromObject(EndpointRecord record, JsonObject scansJson) {
        scansJson.entrySet().forEach(entry -> {
            String tid = entry.getKey();
            JsonObject tsJson = entry.getValue().getAsJsonObject();
            record.recordScanComplete(tid,
                    tsJson.has("payloadsSent") ? tsJson.get("payloadsSent").getAsInt() : 0,
                    tsJson.has("findings") ? tsJson.get("findings").getAsInt() : 0);
        });
    }

    /** Clear all coverage data from memory and persistence. */
    public void clearAll() {
        data.clear();
        saveToPersistence();
        notifyChange();
        log.info("Coverage data cleared.");
    }

    private void notifyChange() {
        if (changeListener != null)
            changeListener.accept(null);
    }

    /**
     * Schedule a debounced save — waits 2 seconds after the last call,
     * so rapid proxy traffic doesn't cause a save on every single request.
     */
    private void scheduleSave() {
        ScheduledFuture<?> prev = pendingSave;
        if (prev != null) prev.cancel(false);
        pendingSave = saveScheduler.schedule(this::saveToPersistence, 2, TimeUnit.SECONDS);
    }

    public void setChangeListener(Consumer<Void> listener) {
        this.changeListener = listener;
    }

    public int getTotalEndpoints() {
        return data.values().stream().mapToInt(Map::size).sum();
    }
}
