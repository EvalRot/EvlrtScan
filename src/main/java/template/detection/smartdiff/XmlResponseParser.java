package template.detection.smartdiff;

import org.w3c.dom.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Logger;

/**
 * Parses XML response body into content and structure maps.
 * Keys use XPath-like notation (e.g. /root/items/item[0]/name).
 */
public class XmlResponseParser {

    private static final Logger log = Logger.getLogger(XmlResponseParser.class.getName());

    public static ParsedResponse parse(String body) {
        Map<String, String> contentMap = new LinkedHashMap<>();
        Map<String, String> structureMap = new LinkedHashMap<>();

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Disable external entities for security
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(
                    new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
            doc.getDocumentElement().normalize();

            traverseNode(doc.getDocumentElement(), "", contentMap, structureMap);
        } catch (Exception e) {
            log.fine("Failed to parse XML: " + e.getMessage());
        }

        return new ParsedResponse(contentMap, structureMap);
    }

    private static void traverseNode(Node node, String parentPath,
            Map<String, String> contentMap, Map<String, String> structureMap) {
        if (node == null || node.getNodeType() != Node.ELEMENT_NODE)
            return;

        String tagName = node.getNodeName();
        String path = parentPath + "/" + tagName;

        // Structure: tag name + attribute names
        StringBuilder structDesc = new StringBuilder(tagName);
        NamedNodeMap attrs = node.getAttributes();
        if (attrs != null && attrs.getLength() > 0) {
            List<String> attrNames = new ArrayList<>();
            for (int i = 0; i < attrs.getLength(); i++) {
                attrNames.add(attrs.item(i).getNodeName());
            }
            Collections.sort(attrNames);
            structDesc.append(attrNames);
        }
        structureMap.put(path, structDesc.toString());

        // Content: text content of this node (direct text only)
        String text = getDirectText(node);
        if (!text.isBlank()) {
            contentMap.put(path, ResponseParser.normalize(text));
        }

        // Recurse into child elements with sibling indexing
        Map<String, Integer> childCounters = new HashMap<>();
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                String childTag = child.getNodeName();
                int idx = childCounters.getOrDefault(childTag, 0);
                childCounters.put(childTag, idx + 1);

                String childPath = path + "/" + childTag + "[" + idx + "]";
                // Use childPath directly (without extra prefix from recursion)
                traverseNodeIndexed(child, childPath, contentMap, structureMap);
            }
        }
    }

    private static void traverseNodeIndexed(Node node, String path,
            Map<String, String> contentMap, Map<String, String> structureMap) {
        if (node == null || node.getNodeType() != Node.ELEMENT_NODE)
            return;

        String tagName = node.getNodeName();

        // Structure
        StringBuilder structDesc = new StringBuilder(tagName);
        NamedNodeMap attrs = node.getAttributes();
        if (attrs != null && attrs.getLength() > 0) {
            List<String> attrNames = new ArrayList<>();
            for (int i = 0; i < attrs.getLength(); i++) {
                attrNames.add(attrs.item(i).getNodeName());
            }
            Collections.sort(attrNames);
            structDesc.append(attrNames);
        }
        structureMap.put(path, structDesc.toString());

        // Content
        String text = getDirectText(node);
        if (!text.isBlank()) {
            contentMap.put(path, ResponseParser.normalize(text));
        }

        // Recurse
        Map<String, Integer> childCounters = new HashMap<>();
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                String childTag = child.getNodeName();
                int idx = childCounters.getOrDefault(childTag, 0);
                childCounters.put(childTag, idx + 1);
                traverseNodeIndexed(child, path + "/" + childTag + "[" + idx + "]",
                        contentMap, structureMap);
            }
        }
    }

    /**
     * Get direct text content only (not from child elements).
     */
    private static String getDirectText(Node node) {
        StringBuilder sb = new StringBuilder();
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.TEXT_NODE || child.getNodeType() == Node.CDATA_SECTION_NODE) {
                sb.append(child.getTextContent());
            }
        }
        return sb.toString().trim();
    }
}
