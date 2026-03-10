package engine;

/**
 * Represents a single injection target point in an HTTP request.
 */
public class InsertionPoint {

    public enum Type {
        QUERY_PARAM,
        BODY_PARAM, // form-encoded
        JSON_VALUE, // JSON body value
        XML_VALUE, // XML body value
        COOKIE,
        HEADER,
        URL_PATH_SEGMENT
    }

    private final Type type;
    private final String name; // parameter/header/cookie name
    private final String originalValue;
    private final String jsonPath; // for JSON_VALUE: dot-notation path e.g. "user.name"

    public InsertionPoint(Type type, String name, String originalValue) {
        this(type, name, originalValue, null);
    }

    public InsertionPoint(Type type, String name, String originalValue, String jsonPath) {
        this.type = type;
        this.name = name;
        this.originalValue = originalValue;
        this.jsonPath = jsonPath;
    }

    public Type getType() {
        return type;
    }

    public String getName() {
        return name;
    }

    public String getOriginalValue() {
        return originalValue;
    }

    public String getJsonPath() {
        return jsonPath;
    }

    public String getDisplayLabel() {
        return switch (type) {
            case QUERY_PARAM -> "Query: " + name;
            case BODY_PARAM -> "Body: " + name;
            case JSON_VALUE -> "JSON: " + (jsonPath != null ? jsonPath : name);
            case XML_VALUE -> "XML: " + name;
            case COOKIE -> "Cookie: " + name;
            case HEADER -> "Header: " + name;
            case URL_PATH_SEGMENT -> "Path: /" + name;
        };
    }

    @Override
    public String toString() {
        return getDisplayLabel() + " = \"" + truncate(originalValue, 40) + "\"";
    }

    private String truncate(String s, int max) {
        if (s == null)
            return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
