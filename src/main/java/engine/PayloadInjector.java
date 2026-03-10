package engine;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.*;
import engine.EncodingDetector.Encoding;
import template.ScanTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Injects a payload into a specific insertion point of an HTTP request.
 * Encoding-aware: detects the original value's encoding, decodes it,
 * applies the payload strategy in plain text, and re-encodes into
 * the same (or forced) format.
 */
public class PayloadInjector {

    /**
     * Inject with automatic encoding detection.
     */
    public HttpRequest inject(HttpRequest request, InsertionPoint point, String payload,
            ScanTemplate.InjectionStrategy strategy) {
        return inject(request, point, payload, strategy, null);
    }

    /**
     * Inject with optional forced encoding override.
     *
     * @param forcedEncoding if non-null, the final value is encoded in this format
     *                       instead of the auto-detected format.
     */
    public HttpRequest inject(HttpRequest request, InsertionPoint point, String payload,
            ScanTemplate.InjectionStrategy strategy, Encoding forcedEncoding) {

        String originalValue = point.getOriginalValue();
        Encoding detected = EncodingDetector.detect(originalValue);

        // Decode original to plain text
        String plainOriginal = PayloadEncoder.decode(originalValue, detected);

        // Apply injection strategy in plain text
        String plainResult = buildValue(plainOriginal, payload, strategy);

        // Determine output encoding
        Encoding outputEncoding = (forcedEncoding != null) ? forcedEncoding : detected;

        // For query and body params, if the detected encoding was PLAIN,
        // we MUST upgrade to URL_ENCODED. This ensures the injected payload
        // (which might contain spaces, quotes, etc.) is properly URL encoded.
        // Burp's Montoya API does not always auto URL-encode values passed to
        // withAddedParameters().
        if (outputEncoding == Encoding.PLAIN &&
                (point.getType() == InsertionPoint.Type.QUERY_PARAM ||
                        point.getType() == InsertionPoint.Type.BODY_PARAM)) {
            outputEncoding = Encoding.URL_ENCODED;
        }

        // Apply full encoding ourselves for all parameter types
        String finalValue = PayloadEncoder.encode(plainResult, outputEncoding);

        return switch (point.getType()) {
            case QUERY_PARAM -> injectQueryParam(request, point.getName(), finalValue);
            case BODY_PARAM -> injectBodyParam(request, point.getName(), finalValue);
            case JSON_VALUE -> injectJson(request, point.getJsonPath(), point.getName(), finalValue);
            case COOKIE -> injectCookie(request, point.getName(), finalValue);
            case HEADER -> injectHeader(request, point.getName(), finalValue);
            case URL_PATH_SEGMENT -> injectPathSegment(request, point.getName(), plainResult);
            default -> request;
        };
    }

    private String buildValue(String original, String payload, ScanTemplate.InjectionStrategy strategy) {
        return switch (strategy) {
            case APPEND -> (original != null ? original : "") + payload;
            case REPLACE -> payload;
            case INSERT -> payload + (original != null ? original : "");
        };
    }

    private HttpRequest injectQueryParam(HttpRequest req, String name, String value) {
        HttpRequest updated = req;
        for (var p : req.parameters()) {
            if (p.name().equals(name) && p.type() == HttpParameterType.URL) {
                updated = updated.withRemovedParameters(p);
            }
        }
        return updated.withAddedParameters(HttpParameter.urlParameter(name, value));
    }

    private HttpRequest injectBodyParam(HttpRequest req, String name, String value) {
        HttpRequest updated = req;
        for (var p : req.parameters()) {
            if (p.name().equals(name) && p.type() == HttpParameterType.BODY) {
                updated = updated.withRemovedParameters(p);
            }
        }
        return updated.withAddedParameters(HttpParameter.bodyParameter(name, value));
    }

    private HttpRequest injectJson(HttpRequest req, String jsonPath, String name, String value) {
        String body = req.bodyToString();
        try {
            JsonElement el = JsonParser.parseString(body);
            setJsonValue(el, jsonPath != null ? jsonPath.split("\\.") : new String[] { name }, 0, value);
            return req.withBody(new Gson().toJson(el));
        } catch (Exception e) {
            return req;
        }
    }

    private void setJsonValue(JsonElement el, String[] path, int idx, String value) {
        if (el.isJsonObject() && idx < path.length) {
            JsonObject obj = el.getAsJsonObject();
            String key = path[idx].replaceAll("\\[\\d+\\]$", "");
            if (idx == path.length - 1) {
                obj.addProperty(key, value);
            } else if (obj.has(key)) {
                setJsonValue(obj.get(key), path, idx + 1, value);
            }
        }
    }

    private HttpRequest injectCookie(HttpRequest req, String name, String value) {
        HttpRequest updated = req;
        for (var p : req.parameters()) {
            if (p.name().equals(name) && p.type() == HttpParameterType.COOKIE) {
                updated = updated.withRemovedParameters(p);
            }
        }
        return updated.withAddedParameters(HttpParameter.cookieParameter(name, value));
    }

    private HttpRequest injectHeader(HttpRequest req, String name, String value) {
        var headers = new ArrayList<>(req.headers());
        headers.removeIf(h -> h.name().equalsIgnoreCase(name));
        headers.add(burp.api.montoya.http.message.HttpHeader.httpHeader(name, value));
        return req.withUpdatedHeaders(headers);
    }

    private HttpRequest injectPathSegment(HttpRequest req, String originalSegment, String newValue) {
        String path = req.path();
        String newPath = path.replace("/" + originalSegment, "/" + urlEncode(newValue));
        return req.withPath(newPath);
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
