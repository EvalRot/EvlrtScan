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
import java.util.concurrent.ThreadLocalRandom;

/**
 * Injects a payload into a specific insertion point of an HTTP request.
 * Encoding-aware: detects the original value's encoding, decodes it,
 * applies the payload strategy in plain text, and re-encodes into
 * the same (or forced) format.
 */
public class PayloadInjector {

    private static final String PLACEHOLDER_ORIGINAL = "{{ORIGINAL}}";
    private static final String PLACEHOLDER_RANDOM = "{{RANDOM}}";

    /**
     * Inject with automatic encoding detection (no json_type).
     */
    public HttpRequest inject(HttpRequest request, InsertionPoint point, String payload,
            ScanTemplate.InjectionStrategy strategy) {
        return inject(request, point, payload, strategy, null, "keep");
    }

    /**
     * Inject with optional forced encoding override (no json_type).
     */
    public HttpRequest inject(HttpRequest request, InsertionPoint point, String payload,
            ScanTemplate.InjectionStrategy strategy, Encoding forcedEncoding) {
        return inject(request, point, payload, strategy, forcedEncoding, "keep");
    }

    /**
     * Full inject with jsonType support.
     *
     * @param forcedEncoding if non-null, the final value is encoded in this format
     *                       instead of the auto-detected format.
     * @param jsonType       "keep", "object", or "array" — controls JSON structural wrapping.
     */
    public HttpRequest inject(HttpRequest request, InsertionPoint point, String payload,
            ScanTemplate.InjectionStrategy strategy, Encoding forcedEncoding, String jsonType) {

        String originalValue = point.getOriginalValue();
        Encoding detected = EncodingDetector.detect(originalValue);

        // Decode original to plain text
        String plainOriginal = PayloadEncoder.decode(originalValue, detected);

        // Apply injection strategy in plain text
        String plainResult = buildValue(plainOriginal, payload, strategy);

        // Determine output encoding
        Encoding outputEncoding = (forcedEncoding != null) ? forcedEncoding : detected;

        // For query and body params, if the detected encoding was PLAIN,
        // we MUST upgrade to URL_ENCODED.
        if (outputEncoding == Encoding.PLAIN &&
                (point.getType() == InsertionPoint.Type.QUERY_PARAM ||
                        point.getType() == InsertionPoint.Type.BODY_PARAM)) {
            outputEncoding = Encoding.URL_ENCODED;
        }

        // For JSON insertion points, handle structural json_type wrapping
        if (point.getType() == InsertionPoint.Type.JSON_VALUE) {
            return injectJson(request, point.getJsonPath(), point.getName(),
                    plainResult, jsonType);
        }

        // Apply full encoding ourselves for all other parameter types
        String finalValue = PayloadEncoder.encode(plainResult, outputEncoding);

        return switch (point.getType()) {
            case QUERY_PARAM -> injectQueryParam(request, point.getName(), finalValue);
            case BODY_PARAM -> injectBodyParam(request, point.getName(), finalValue);
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
            case WRAP -> resolvePlaceholders(payload, original != null ? original : "");
        };
    }

    // ---- WRAP placeholder resolution -----------------------------------

    /**
     * Replace {{ORIGINAL}} with the original value and {{RANDOM}} with a
     * type-aware random value of the same length and format.
     */
    private String resolvePlaceholders(String payloadTemplate, String originalValue) {
        String result = payloadTemplate;
        if (result.contains(PLACEHOLDER_ORIGINAL)) {
            result = result.replace(PLACEHOLDER_ORIGINAL, originalValue);
        }
        if (result.contains(PLACEHOLDER_RANDOM)) {
            String randomValue = generateRandom(originalValue);
            result = result.replace(PLACEHOLDER_RANDOM, randomValue);
        }
        return result;
    }

    /**
     * Detect the type of the original value and generate a random value
     * of the same length and matching format.
     */
    private String generateRandom(String original) {
        if (original == null || original.isEmpty()) {
            return "x";
        }

        // GUID detection: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        if (isGuid(original)) {
            return UUID.randomUUID().toString();
        }

        // Number detection (integer or decimal)
        if (isNumeric(original)) {
            return generateRandomNumber(original);
        }

        // Boolean detection
        if ("true".equalsIgnoreCase(original) || "false".equalsIgnoreCase(original)) {
            // Flip the boolean
            return "true".equalsIgnoreCase(original) ? "false" : "true";
        }

        // Default: random alphanumeric string of the same length
        return generateRandomString(original.length());
    }

    private boolean isGuid(String s) {
        return s.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    }

    private boolean isNumeric(String s) {
        if (s.isEmpty()) return false;
        int start = 0;
        if (s.charAt(0) == '-') start = 1;
        if (start >= s.length()) return false;
        boolean hasDot = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.') {
                if (hasDot) return false;
                hasDot = true;
            } else if (!Character.isDigit(c)) {
                return false;
            }
        }
        return true;
    }

    private String generateRandomNumber(String original) {
        int len = original.length();
        boolean negative = original.startsWith("-");
        boolean hasDot = original.contains(".");

        StringBuilder sb = new StringBuilder();
        if (negative) sb.append('-');

        ThreadLocalRandom rng = ThreadLocalRandom.current();
        int digits = len - (negative ? 1 : 0) - (hasDot ? 1 : 0);

        if (hasDot) {
            int dotPos = original.indexOf('.');
            int intDigits = dotPos - (negative ? 1 : 0);
            int fracDigits = digits - intDigits;

            // Integer part (first digit 1-9, rest 0-9)
            if (intDigits > 0) {
                sb.append(rng.nextInt(1, 10));
                for (int i = 1; i < intDigits; i++) sb.append(rng.nextInt(0, 10));
            } else {
                sb.append('0');
            }
            sb.append('.');
            for (int i = 0; i < fracDigits; i++) sb.append(rng.nextInt(0, 10));
        } else {
            // Integer: first digit 1-9, rest 0-9
            if (digits > 0) {
                sb.append(rng.nextInt(1, 10));
                for (int i = 1; i < digits; i++) sb.append(rng.nextInt(0, 10));
            } else {
                sb.append('0');
            }
        }

        return sb.toString();
    }

    private String generateRandomString(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder(length);
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(rng.nextInt(chars.length())));
        }
        return sb.toString();
    }

    // ---- JSON injection with structural json_type ----------------------

    private HttpRequest injectJson(HttpRequest req, String jsonPath, String name,
            String plainResult, String jsonType) {
        String body = req.bodyToString();
        try {
            JsonElement el = JsonParser.parseString(body);
            setJsonValue(el, jsonPath != null ? jsonPath.split("\\.") : new String[] { name },
                    0, plainResult, jsonType);
            return req.withBody(new Gson().toJson(el));
        } catch (Exception e) {
            return req;
        }
    }

    private void setJsonValue(JsonElement el, String[] path, int idx,
            String value, String jsonType) {
        if (el.isJsonObject() && idx < path.length) {
            JsonObject obj = el.getAsJsonObject();
            String key = path[idx].replaceAll("\\[\\d+\\]$", "");
            if (idx == path.length - 1) {
                // Final node: apply jsonType-aware insertion
                JsonElement newEl = buildJsonElement(value, jsonType);
                obj.add(key, newEl);
            } else if (obj.has(key)) {
                setJsonValue(obj.get(key), path, idx + 1, value, jsonType);
            }
        }
    }

    /**
     * Build the final JsonElement based on json_type.
     * - "keep": preserve the original JSON type if possible (number/boolean/string).
     * - "object": wrap the value in { } and parse as a JsonObject.
     * - "array": wrap the value in [ ] and parse as a JsonArray.
     */
    private JsonElement buildJsonElement(String value, String jsonType) {
        return switch (jsonType != null ? jsonType.toLowerCase() : "keep") {
            case "object" -> {
                try {
                    yield JsonParser.parseString("{" + value + "}");
                } catch (JsonSyntaxException e) {
                    yield new JsonPrimitive(value);
                }
            }
            case "array" -> {
                try {
                    yield JsonParser.parseString("[" + value + "]");
                } catch (JsonSyntaxException e) {
                    yield new JsonPrimitive(value);
                }
            }
            default -> { // "keep"
                // Try to preserve the natural JSON type
                if ("true".equals(value) || "false".equals(value)) {
                    yield new JsonPrimitive(Boolean.parseBoolean(value));
                }
                try {
                    double num = Double.parseDouble(value);
                    if (value.contains(".")) {
                        yield new JsonPrimitive(num);
                    } else {
                        yield new JsonPrimitive(Long.parseLong(value));
                    }
                } catch (NumberFormatException e) {
                    yield new JsonPrimitive(value);
                }
            }
        };
    }

    // ---- Other injection methods (unchanged) ---------------------------

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
