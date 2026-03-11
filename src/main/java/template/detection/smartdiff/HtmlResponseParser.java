package template.detection.smartdiff;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;
import java.util.logging.Logger;

/**
 * Parses HTML response body into content and structure maps.
 * Extracts only significant elements: h1-h6, p, td, th, li, a, div, span.
 * Content keys use DOM path notation (e.g. html>body>div.main>p[0]).
 */
public class HtmlResponseParser {

    private static final Logger log = Logger.getLogger(HtmlResponseParser.class.getName());

    private static final Set<String> SIGNIFICANT_TAGS = Set.of(
            "h1", "h2", "h3", "h4", "h5", "h6",
            "p", "td", "th", "li", "a", "div", "span");

    public static ParsedResponse parse(String body) {
        Map<String, String> contentMap = new LinkedHashMap<>();
        Map<String, String> structureMap = new LinkedHashMap<>();

        try {
            Document doc = Jsoup.parse(body);
            traverseElement(doc.body(), "", contentMap, structureMap, new HashMap<>());
        } catch (Exception e) {
            log.fine("Failed to parse HTML: " + e.getMessage());
        }

        return new ParsedResponse(contentMap, structureMap);
    }

    private static void traverseElement(Element element, String parentPath,
            Map<String, String> contentMap, Map<String, String> structureMap,
            Map<String, Integer> siblingCounters) {
        if (element == null)
            return;

        String tagName = element.tagName().toLowerCase();
        String path = buildPath(parentPath, element, siblingCounters);

        if (SIGNIFICANT_TAGS.contains(tagName)) {
            // Content: own text (not children's text) normalized
            String ownText = element.ownText();
            if (!ownText.isBlank()) {
                contentMap.put(path, ResponseParser.normalize(ownText));
            }
            // Structure: tag name + sorted attribute names (without values)
            List<String> attrNames = new ArrayList<>();
            element.attributes().forEach(attr -> attrNames.add(attr.getKey()));
            Collections.sort(attrNames);
            String structureDesc = tagName + (attrNames.isEmpty() ? "" : attrNames.toString());
            structureMap.put(path, structureDesc);
        }

        // Recurse into children with fresh sibling counters per parent
        Map<String, Integer> childCounters = new HashMap<>();
        for (Element child : element.children()) {
            traverseElement(child, path, contentMap, structureMap, childCounters);
        }
    }

    private static String buildPath(String parentPath, Element element,
            Map<String, Integer> siblingCounters) {
        String tag = element.tagName().toLowerCase();

        // Build identifier: tag + optional id/class
        StringBuilder ident = new StringBuilder(tag);
        String id = element.id();
        if (id != null && !id.isEmpty()) {
            ident.append("#").append(id);
        } else {
            String cls = element.className();
            if (cls != null && !cls.isEmpty()) {
                ident.append(".").append(cls.split("\\s+")[0]); // use first class
            }
        }

        // Add sibling index
        String key = ident.toString();
        int idx = siblingCounters.getOrDefault(key, 0);
        siblingCounters.put(key, idx + 1);

        String fullIdent = key + "[" + idx + "]";
        return parentPath.isEmpty() ? fullIdent : parentPath + ">" + fullIdent;
    }
}
