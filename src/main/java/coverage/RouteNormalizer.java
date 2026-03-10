package coverage;

import java.util.regex.Pattern;

/**
 * Normalizes URL paths to canonical route patterns.
 * E.g.: /users/123 → /users/{id}
 * /files/a1b2c3d4-... → /files/{uuid}
 */
public class RouteNormalizer {

    // UUID: 8-4-4-4-12 hex chars
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    // Hex hash (16+ chars)
    private static final Pattern HASH_PATTERN = Pattern.compile("[0-9a-fA-F]{16,}");

    // Pure numeric ID
    private static final Pattern NUMERIC_PATTERN = Pattern.compile("^\\d+$");

    // Base64-ish (long alphanumeric+/= with length > 12)
    private static final Pattern BASE64_PATTERN = Pattern.compile("[A-Za-z0-9+/=_-]{20,}");

    /**
     * Normalizes a path, stripping the query string first.
     * E.g. "/api/users/42?debug=true" → "/api/users/{id}"
     */
    public String normalize(String rawPath) {
        if (rawPath == null || rawPath.isBlank())
            return "/";

        // Strip query string
        String path = rawPath.split("\\?")[0];
        // Strip trailing slash (keep root)
        if (path.length() > 1 && path.endsWith("/"))
            path = path.substring(0, path.length() - 1);

        String[] segments = path.split("/");
        StringBuilder normalized = new StringBuilder();

        for (String seg : segments) {
            if (seg.isBlank()) {
                normalized.append("/");
                continue;
            }
            normalized.append(normalizeSegment(seg)).append("/");
        }

        String result = normalized.toString();
        // Ensure leading slash, remove trailing (unless root)
        if (!result.startsWith("/"))
            result = "/" + result;
        if (result.length() > 1 && result.endsWith("/"))
            result = result.substring(0, result.length() - 1);

        return result;
    }

    private String normalizeSegment(String seg) {
        if (NUMERIC_PATTERN.matcher(seg).matches())
            return "{id}";
        if (UUID_PATTERN.matcher(seg).matches())
            return "{uuid}";
        if (HASH_PATTERN.matcher(seg).matches())
            return "{hash}";
        if (BASE64_PATTERN.matcher(seg).matches())
            return "{token}";
        return seg;
    }

    /**
     * Build a route key combining method and normalized path.
     * E.g. "GET /api/users/{id}"
     */
    public String routeKey(String method, String path) {
        return method.toUpperCase() + " " + normalize(path);
    }
}
