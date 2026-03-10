package engine;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.*;

import java.util.*;

/**
 * Parses an HTTP request and extracts all available insertion points
 * that can be shown in the Scan Configuration Dialog.
 */
public class InsertionPointParser {

    public List<InsertionPoint> parse(HttpRequest request) {
        List<InsertionPoint> points = new ArrayList<>();

        // Query parameters
        for (ParsedHttpParameter p : request.parameters()) {
            if (p.type() == HttpParameterType.URL) {
                points.add(new InsertionPoint(InsertionPoint.Type.QUERY_PARAM, p.name(), p.value()));
            }
        }

        // Body parameters (form-encoded)
        String contentType = getContentType(request);
        if (contentType.contains("application/x-www-form-urlencoded")) {
            for (ParsedHttpParameter p : request.parameters()) {
                if (p.type() == HttpParameterType.BODY) {
                    points.add(new InsertionPoint(InsertionPoint.Type.BODY_PARAM, p.name(), p.value()));
                }
            }
        }

        // JSON body
        if (contentType.contains("application/json")) {
            String body = request.bodyToString();
            if (!body.isBlank()) {
                try {
                    JsonElement el = JsonParser.parseString(body);
                    extractJsonPoints(el, "", points);
                } catch (JsonSyntaxException e) {
                    // Not valid JSON, ignore
                }
            }
        }

        // Cookies
        for (ParsedHttpParameter p : request.parameters()) {
            if (p.type() == HttpParameterType.COOKIE) {
                points.add(new InsertionPoint(InsertionPoint.Type.COOKIE, p.name(), p.value()));
            }
        }

        // Interesting headers (skip standard boring ones)
        Set<String> skipHeaders = Set.of("host", "content-length", "connection",
                "accept-encoding", "cache-control", "accept", "content-type",
                "authorization", "referer", "priority", "user-agent", "accept-language");

        for (var h : request.headers()) {
            String nameLower = h.name().toLowerCase();
            if (!skipHeaders.contains(nameLower) && !nameLower.startsWith("sec-")) {
                points.add(new InsertionPoint(InsertionPoint.Type.HEADER, h.name(), h.value()));
            }
        }

        // URL path segments (non-empty, non-trivial)
        String path = request.path().split("\\?")[0]; // strip query
        String[] segments = path.split("/");
        for (String seg : segments) {
            if (!seg.isBlank() && !seg.equals("api") && !seg.equals("v1") && !seg.equals("v2")) {
                points.add(new InsertionPoint(InsertionPoint.Type.URL_PATH_SEGMENT, seg, seg));
            }
        }

        return points;
    }

    private void extractJsonPoints(JsonElement el, String path, List<InsertionPoint> points) {
        if (el.isJsonObject()) {
            JsonObject obj = el.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String childPath = path.isEmpty() ? entry.getKey() : path + "." + entry.getKey();
                JsonElement child = entry.getValue();
                if (child.isJsonPrimitive()) {
                    points.add(new InsertionPoint(InsertionPoint.Type.JSON_VALUE,
                            entry.getKey(), child.getAsString(), childPath));
                } else {
                    extractJsonPoints(child, childPath, points);
                }
            }
        } else if (el.isJsonArray()) {
            JsonArray arr = el.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                extractJsonPoints(arr.get(i), path + "[" + i + "]", points);
            }
        }
    }

    private String getContentType(HttpRequest request) {
        return request.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("content-type"))
                .map(h -> h.value().toLowerCase())
                .findFirst().orElse("");
    }
}
