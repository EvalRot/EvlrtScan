package template.detection.smartdiff;

import com.google.gson.*;

import java.util.*;
import java.util.logging.Logger;

/**
 * Parses JSON response body into content and structure maps.
 * Keys use JSONPath-like notation (e.g. $.users[0].name).
 * Object keys are sorted before traversal for deterministic ordering.
 */
public class JsonResponseParser {

    private static final Logger log = Logger.getLogger(JsonResponseParser.class.getName());

    public static ParsedResponse parse(String body) {
        Map<String, String> contentMap = new LinkedHashMap<>();
        Map<String, String> structureMap = new LinkedHashMap<>();

        try {
            JsonElement root = JsonParser.parseString(body);
            traverse(root, "$", contentMap, structureMap);
        } catch (JsonSyntaxException e) {
            log.fine("Failed to parse JSON: " + e.getMessage());
        }

        return new ParsedResponse(contentMap, structureMap);
    }

    private static void traverse(JsonElement element, String path,
            Map<String, String> contentMap, Map<String, String> structureMap) {
        if (element == null || element.isJsonNull()) {
            contentMap.put(path, "null");
            structureMap.put(path, "Null");
        } else if (element.isJsonPrimitive()) {
            JsonPrimitive prim = element.getAsJsonPrimitive();
            String value = ResponseParser.normalize(prim.getAsString());
            contentMap.put(path, value);

            if (prim.isNumber())
                structureMap.put(path, "Number");
            else if (prim.isBoolean())
                structureMap.put(path, "Boolean");
            else
                structureMap.put(path, "String");
        } else if (element.isJsonArray()) {
            JsonArray arr = element.getAsJsonArray();
            structureMap.put(path, "Array");
            for (int i = 0; i < arr.size(); i++) {
                traverse(arr.get(i), path + "[" + i + "]", contentMap, structureMap);
            }
        } else if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            structureMap.put(path, "Object");
            // Sort keys for deterministic traversal
            List<String> keys = new ArrayList<>(obj.keySet());
            Collections.sort(keys);
            for (String key : keys) {
                traverse(obj.get(key), path + "." + key, contentMap, structureMap);
            }
        }
    }
}
