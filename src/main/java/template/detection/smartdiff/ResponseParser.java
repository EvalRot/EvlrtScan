package template.detection.smartdiff;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Detects response content type and dispatches to the appropriate parser.
 * Supports JSON, HTML, and XML.
 */
public class ResponseParser {

    private static final Logger log = Logger.getLogger(ResponseParser.class.getName());

    /**
     * Parse the response body into content and structure maps.
     *
     * @param body        response body string
     * @param contentType Content-Type header value (may be null)
     * @return ParsedResponse with content and structure maps
     */
    public static ParsedResponse parse(String body, String contentType) {
        if (body == null || body.isBlank()) {
            return new ParsedResponse(new LinkedHashMap<>(), new LinkedHashMap<>());
        }

        ContentType type = detectType(body, contentType);

        return switch (type) {
            case JSON -> JsonResponseParser.parse(body);
            case HTML -> HtmlResponseParser.parse(body);
            case XML -> XmlResponseParser.parse(body);
            case UNKNOWN -> {
                log.fine("Unknown content type, treating as plain text");
                // Fallback: single entry with the whole body
                Map<String, String> content = new LinkedHashMap<>();
                Map<String, String> structure = new LinkedHashMap<>();
                content.put("$", normalize(body));
                structure.put("$", "text");
                yield new ParsedResponse(content, structure);
            }
        };
    }

    enum ContentType {
        JSON, HTML, XML, UNKNOWN
    }

    static ContentType detectType(String body, String contentType) {
        // 1. Check Content-Type header
        if (contentType != null) {
            String ct = contentType.toLowerCase();
            if (ct.contains("application/json") || ct.contains("text/json"))
                return ContentType.JSON;
            if (ct.contains("text/html") || ct.contains("application/xhtml"))
                return ContentType.HTML;
            if (ct.contains("text/xml") || ct.contains("application/xml"))
                return ContentType.XML;
        }

        // 2. Heuristic fallback based on body
        String trimmed = body.trim();
        if (trimmed.isEmpty())
            return ContentType.UNKNOWN;

        char first = trimmed.charAt(0);
        if (first == '{' || first == '[')
            return ContentType.JSON;
        if (first == '<') {
            String lower = trimmed.substring(0, Math.min(trimmed.length(), 500)).toLowerCase();
            if (lower.contains("<?xml"))
                return ContentType.XML;
            if (lower.contains("<html") || lower.contains("<!doctype html"))
                return ContentType.HTML;
            // Default XML for any <tag> content
            return ContentType.XML;
        }

        return ContentType.UNKNOWN;
    }

    static String normalize(String value) {
        if (value == null)
            return "";
        return value.trim().toLowerCase().replaceAll("\\s+", " ");
    }
}
