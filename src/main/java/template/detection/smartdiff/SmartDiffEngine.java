package template.detection.smartdiff;

import java.util.*;
import java.util.logging.Logger;

/**
 * SmartDiff comparison engine that:
 * <ol>
 * <li>Builds Dynamic Mask from repeated baseline responses</li>
 * <li>Builds Reflection Mask from probe response + marker</li>
 * <li>Computes Jaccard similarity on masked content/structure maps</li>
 * </ol>
 */
public class SmartDiffEngine {

    private static final Logger log = Logger.getLogger(SmartDiffEngine.class.getName());

    /**
     * Build Dynamic Mask: keys whose values change across identical requests.
     * Compare resp0 with resp1 and resp2 — if value differs for a key, that key is
     * dynamic.
     *
     * @param contentType Content-Type header
     * @param body0       original response body
     * @param body1       first repeat body
     * @param body2       second repeat body
     * @return set of keys that are dynamic (change without input change)
     */
    public static Set<String> buildDynamicMask(String contentType,
            String body0, String body1, String body2) {
        ParsedResponse parsed0 = ResponseParser.parse(body0, contentType);
        ParsedResponse parsed1 = ResponseParser.parse(body1, contentType);
        ParsedResponse parsed2 = ResponseParser.parse(body2, contentType);

        Set<String> dynamicKeys = new HashSet<>();

        // Check content maps: if value differs in ANY repeat, key is dynamic
        for (String key : parsed0.getContentMap().keySet()) {
            String val0 = parsed0.getContentMap().get(key);
            String val1 = parsed1.getContentMap().getOrDefault(key, "");
            String val2 = parsed2.getContentMap().getOrDefault(key, "");

            if (!val0.equals(val1) || !val0.equals(val2)) {
                dynamicKeys.add(key);
            }
        }

        // Also check keys that appear in repeats but not in original
        for (String key : parsed1.getContentMap().keySet()) {
            if (!parsed0.getContentMap().containsKey(key)) {
                dynamicKeys.add(key);
            }
        }
        for (String key : parsed2.getContentMap().keySet()) {
            if (!parsed0.getContentMap().containsKey(key)) {
                dynamicKeys.add(key);
            }
        }

        log.fine("Dynamic mask: " + dynamicKeys.size() + " keys flagged as dynamic");
        return dynamicKeys;
    }

    /**
     * Build Reflection Mask: keys whose values contain the probe marker.
     *
     * @param contentType Content-Type header
     * @param probeBody   response body from the probe request
     * @param marker      the unique marker string injected in the probe
     * @return set of keys where the marker was reflected
     */
    public static Set<String> buildReflectionMask(String contentType,
            String probeBody, String marker) {
        ParsedResponse parsed = ResponseParser.parse(probeBody, contentType);
        Set<String> reflectedKeys = new HashSet<>();
        String markerLower = marker.toLowerCase();

        for (Map.Entry<String, String> entry : parsed.getContentMap().entrySet()) {
            if (entry.getValue().contains(markerLower)) {
                reflectedKeys.add(entry.getKey());
            }
        }

        log.fine("Reflection mask: " + reflectedKeys.size() + " keys contain marker");
        return reflectedKeys;
    }

    /**
     * Compare two ParsedResponses using Jaccard similarity.
     *
     * @param baseline the masked baseline ParsedResponse
     * @param payload  the masked payload ParsedResponse
     * @return SmartDiffResult with content and structure similarity scores
     */
    public static SmartDiffResult compare(ParsedResponse baseline, ParsedResponse payload) {
        double contentSim = jaccardSimilarity(baseline.getContentMap(), payload.getContentMap());
        double structureSim = jaccardSimilarity(baseline.getStructureMap(), payload.getStructureMap());
        return new SmartDiffResult(contentSim, structureSim);
    }

    /**
     * Jaccard similarity between two maps:
     * J(A,B) = |A ∩ B| / |A ∪ B|
     * where A and B are sets of (key, value) pairs.
     */
    public static double jaccardSimilarity(Map<String, String> mapA, Map<String, String> mapB) {
        if (mapA.isEmpty() && mapB.isEmpty())
            return 1.0;

        // Build sets of (key, value) pairs
        Set<String> setA = new HashSet<>();
        for (Map.Entry<String, String> entry : mapA.entrySet()) {
            setA.add(entry.getKey() + "=" + entry.getValue());
        }

        Set<String> setB = new HashSet<>();
        for (Map.Entry<String, String> entry : mapB.entrySet()) {
            setB.add(entry.getKey() + "=" + entry.getValue());
        }

        // Intersection
        Set<String> intersection = new HashSet<>(setA);
        intersection.retainAll(setB);

        // Union
        Set<String> union = new HashSet<>(setA);
        union.addAll(setB);

        if (union.isEmpty())
            return 1.0;
        return (double) intersection.size() / union.size();
    }
}
