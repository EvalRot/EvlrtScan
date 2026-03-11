package template.detection.smartdiff;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Holds parsed response body as two parallel maps:
 * <ul>
 * <li>contentMap: path → normalized string value</li>
 * <li>structureMap: path → type/tag descriptor</li>
 * </ul>
 */
public class ParsedResponse {

    private final Map<String, String> contentMap;
    private final Map<String, String> structureMap;

    public ParsedResponse(Map<String, String> contentMap, Map<String, String> structureMap) {
        this.contentMap = new LinkedHashMap<>(contentMap);
        this.structureMap = new LinkedHashMap<>(structureMap);
    }

    public Map<String, String> getContentMap() {
        return contentMap;
    }

    public Map<String, String> getStructureMap() {
        return structureMap;
    }

    /**
     * Remove all entries whose keys are in the given mask set.
     * Returns a NEW ParsedResponse with masked-out entries removed.
     */
    public ParsedResponse applyMask(Set<String> mask) {
        Map<String, String> maskedContent = new LinkedHashMap<>(contentMap);
        Map<String, String> maskedStructure = new LinkedHashMap<>(structureMap);
        for (String key : mask) {
            maskedContent.remove(key);
            maskedStructure.remove(key);
        }
        return new ParsedResponse(maskedContent, maskedStructure);
    }

    /**
     * Convenience: apply two masks at once (Dynamic + Reflection).
     */
    public ParsedResponse applyMasks(Set<String> dynamicMask, Set<String> reflectionMask) {
        Map<String, String> maskedContent = new LinkedHashMap<>(contentMap);
        Map<String, String> maskedStructure = new LinkedHashMap<>(structureMap);
        for (String key : dynamicMask) {
            maskedContent.remove(key);
            maskedStructure.remove(key);
        }
        for (String key : reflectionMask) {
            maskedContent.remove(key);
            maskedStructure.remove(key);
        }
        return new ParsedResponse(maskedContent, maskedStructure);
    }

    public boolean isEmpty() {
        return contentMap.isEmpty() && structureMap.isEmpty();
    }
}
