package template;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Loads and validates ScanTemplate objects from YAML files.
 * Maintains a live list of loaded templates that can be reloaded on demand.
 * Thread-safe — templates list uses CopyOnWriteArrayList.
 */
public class TemplateLoader {

    private static final Logger log = Logger.getLogger(TemplateLoader.class.getName());

    /** Currently active templates directory. */
    private volatile Path templatesDir;

    /** Additional directories added via "Load from folder" — survive reloads. */
    private final java.util.Set<Path> additionalDirs = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** Live list of loaded templates — shared with UI and scan dialogs. */
    private final CopyOnWriteArrayList<ScanTemplate> loadedTemplates = new CopyOnWriteArrayList<>();

    /** Optional listener called whenever templates are reloaded. */
    private Consumer<List<ScanTemplate>> onReload;

    public TemplateLoader(String templatesDirPath) {
        this.templatesDir = Paths.get(templatesDirPath);
    }

    // ---- Directory management ------------------------------------------

    public Path getTemplatesDir() {
        return templatesDir;
    }

    /**
     * Change active templates directory and reload from it.
     */
    public void setTemplatesDir(Path newDir) {
        this.templatesDir = newDir;
        reload();
    }

    // ---- Loading -------------------------------------------------------

    /**
     * Load all templates from the current templatesDir.
     * Replaces the live list and fires the onReload callback.
     */
    public List<ScanTemplate> reload() {
        List<ScanTemplate> fresh = loadFromDirectory(templatesDir);

        // Merge templates from additional directories
        Set<String> existingIds = new java.util.HashSet<>();
        fresh.forEach(t -> existingIds.add(t.getId()));
        for (Path dir : additionalDirs) {
            List<ScanTemplate> extra = loadFromDirectory(dir);
            for (ScanTemplate t : extra) {
                if (!existingIds.contains(t.getId())) {
                    fresh.add(t);
                    existingIds.add(t.getId());
                }
            }
        }

        loadedTemplates.clear();
        loadedTemplates.addAll(fresh);
        log.info("Reloaded " + loadedTemplates.size() + " templates from " + templatesDir
                + " + " + additionalDirs.size() + " additional dir(s)");
        if (onReload != null)
            onReload.accept(Collections.unmodifiableList(fresh));
        return fresh;
    }

    /**
     * Load all templates from an arbitrary directory (recursive).
     * Does NOT change the active templates directory.
     */
    public List<ScanTemplate> loadFromDirectory(Path dir) {
        List<ScanTemplate> templates = new ArrayList<>();
        if (!Files.exists(dir)) {
            log.warning("Templates directory not found: " + dir);
            return templates;
        }

        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    String name = file.getFileName().toString();
                    if (name.endsWith(".yaml") || name.endsWith(".yml")) {
                        try {
                            ScanTemplate t = loadFile(file.toFile());
                            if (t != null)
                                templates.add(t);
                        } catch (Exception e) {
                            log.warning("Failed to load template " + file + ": " + e.getMessage());
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.severe("Error walking templates directory: " + e.getMessage());
        }

        log.info("Loaded " + templates.size() + " templates from " + dir);
        return templates;
    }

    /**
     * Load a single template from a file.
     */
    public ScanTemplate loadFile(File file) throws IOException {
        LoaderOptions opts = new LoaderOptions();
        Yaml yaml = new Yaml(new Constructor(Map.class, opts));

        try (InputStream in = new FileInputStream(file)) {
            Map<String, Object> raw = yaml.load(in);
            if (raw == null) {
                log.warning("Empty template file: " + file.getName());
                return null;
            }
            ScanTemplate template = parseTemplate(raw, file.getName());
            if (template == null) {
                return null;
            }

            // Validate template
            TemplateValidator.ValidationResult validation = TemplateValidator.validate(template);
            if (!validation.isValid()) {
                for (String error : validation.getErrors()) {
                    log.warning("Template '" + template.getId() + "' validation error: " + error);
                }
                log.warning("Template '" + template.getId() + "' skipped due to validation errors");
                return null;
            }

            return template;
        }
    }

    /**
     * Returns the live (current) list of loaded templates.
     * Call reload() first to ensure it's up to date.
     */
    public List<ScanTemplate> loadAll() {
        return Collections.unmodifiableList(loadedTemplates);
    }

    /**
     * Add an additional directory that will be included on every reload.
     * Call reload() after this to pick up the templates.
     */
    public void addAdditionalDirectory(Path dir) {
        additionalDirs.add(dir);
    }

    /**
     * Remove an additional directory.
     */
    public void removeAdditionalDirectory(Path dir) {
        additionalDirs.remove(dir);
    }

    /**
     * Set callback fired whenever templates are reloaded.
     */
    public void setOnReload(Consumer<List<ScanTemplate>> listener) {
        this.onReload = listener;
    }

    // ---- Parsing -------------------------------------------------------

    @SuppressWarnings("unchecked")
    private ScanTemplate parseTemplate(Map<String, Object> raw, String fileName) {
        ScanTemplate t = new ScanTemplate();

        t.setId(getString(raw, "id", stripExtension(fileName)));
        t.setName(getString(raw, "name", t.getId()));
        t.setCategory(getString(raw, "category", "custom"));
        t.setSeverity(getString(raw, "severity", "info").toLowerCase());
        t.setAuthor(getString(raw, "author", ""));
        t.setDescription(getString(raw, "description", ""));

        Object tagsObj = raw.get("tags");
        if (tagsObj instanceof List<?> tagList) {
            t.setTags((List<String>) tagList);
        } else {
            t.setTags(new ArrayList<>());
        }

        String strategy = getString(raw, "injection_strategy", "APPEND").toUpperCase();
        try {
            t.setInjectionStrategy(ScanTemplate.InjectionStrategy.valueOf(strategy));
        } catch (IllegalArgumentException e) {
            log.warning("Unknown injection_strategy '" + strategy + "' in " + fileName + ", defaulting to APPEND");
            t.setInjectionStrategy(ScanTemplate.InjectionStrategy.APPEND);
        }

        Object payloadsObj = raw.get("payloads");
        if (payloadsObj instanceof List<?> list) {
            List<ScanTemplate.PayloadEntry> payloads = new ArrayList<>();
            for (Object p : list) {
                if (p instanceof Map<?, ?> pMap) {
                    // Extended format: { value: "...", json_type: "object" }
                    String val = getString((Map<String, Object>) pMap, "value", "");
                    String jt = getString((Map<String, Object>) pMap, "json_type", "keep");
                    payloads.add(new ScanTemplate.PayloadEntry(val, jt));
                } else {
                    // Simple string format
                    payloads.add(new ScanTemplate.PayloadEntry(String.valueOf(p)));
                }
            }
            t.setPayloads(payloads);
        } else {
            t.setPayloads(new ArrayList<>());
        }

        Object groupObj = raw.get("payload_group");
        if (groupObj instanceof List<?> list) {
            List<ScanTemplate.PayloadGroupEntry> group = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof Map<?, ?> itemMap) {
                    ScanTemplate.PayloadGroupEntry entry = new ScanTemplate.PayloadGroupEntry();
                    entry.setId(getString((Map<String, Object>) itemMap, "id", ""));
                    entry.setValue(getString((Map<String, Object>) itemMap, "value", ""));
                    entry.setJsonType(getString((Map<String, Object>) itemMap, "json_type", "keep"));
                    group.add(entry);
                }
            }
            t.setPayloadGroup(group);
        } else {
            t.setPayloadGroup(new ArrayList<>());
        }

        Object detObj = raw.get("detection");
        if (detObj instanceof Map<?, ?> detMap) {
            ScanTemplate.Detection det = new ScanTemplate.Detection();
            det.setLogic(getString((Map<String, Object>) detMap, "logic", "OR").toUpperCase());
            Object baselineObj = ((Map<?, ?>) detMap).get("baseline");
            det.setBaseline(baselineObj == null || Boolean.parseBoolean(String.valueOf(baselineObj)));

            Object rulesObj = ((Map<?, ?>) detMap).get("rules");
            if (rulesObj instanceof List<?> ruleList) {
                List<ScanTemplate.RuleConfig> rules = new ArrayList<>();
                for (Object r : ruleList) {
                    if (r instanceof Map<?, ?> rMap) {
                        rules.add(parseRuleConfig((Map<String, Object>) rMap));
                    }
                }
                det.setRules(rules);
            }
            t.setDetection(det);
        }

        // Validate
        if (t.getPayloads().isEmpty() && t.getPayloadGroup().isEmpty()) {
            log.warning("Template '" + t.getId() + "' has no payloads or payload_group — skipping");
            return null;
        }
        if (t.getDetection() == null || t.getDetection().getRules() == null || t.getDetection().getRules().isEmpty()) {
            log.warning("Template '" + t.getId() + "' has no detection rules — skipping");
            return null;
        }

        return t;
    }

    @SuppressWarnings("unchecked")
    private ScanTemplate.RuleConfig parseRuleConfig(Map<String, Object> raw) {
        ScanTemplate.RuleConfig cfg = new ScanTemplate.RuleConfig();
        cfg.setType(getString(raw, "type", ""));

        Object valObj = raw.get("values");
        if (valObj instanceof List<?> vlist) {
            List<String> vals = new ArrayList<>();
            for (Object v : vlist)
                vals.add(String.valueOf(v));
            cfg.setValues(vals);
        }

        Object csObj = raw.get("case_sensitive");
        if (csObj != null)
            cfg.setCaseSensitive(Boolean.parseBoolean(String.valueOf(csObj)));

        Object toObj = raw.get("to");
        if (toObj instanceof List<?> toList) {
            List<Integer> codes = new ArrayList<>();
            for (Object v : toList)
                codes.add(Integer.parseInt(String.valueOf(v)));
            cfg.setTo(codes);
        }

        Object minMsObj = raw.get("min_ms");
        if (minMsObj == null)
            minMsObj = raw.get("minMs");
        if (minMsObj != null)
            cfg.setMinMs(Integer.parseInt(String.valueOf(minMsObj)));

        Object threshObj = raw.get("threshold");
        if (threshObj != null)
            cfg.setThreshold(Double.parseDouble(String.valueOf(threshObj)));

        cfg.setHeader(getString(raw, "header", null));
        cfg.setPattern(getString(raw, "pattern", null));
        cfg.setExpression(getString(raw, "expression", null));

        Object contentThreshObj = raw.get("content_threshold");
        if (contentThreshObj != null)
            cfg.setContentThreshold(Double.parseDouble(String.valueOf(contentThreshObj)));

        Object structThreshObj = raw.get("structure_threshold");
        if (structThreshObj != null)
            cfg.setStructureThreshold(Double.parseDouble(String.valueOf(structThreshObj)));

        Object varsObj = raw.get("vars");
        if (varsObj instanceof Map<?, ?> varsMap) {
            java.util.LinkedHashMap<String, String> parsedVars = new java.util.LinkedHashMap<>();
            varsMap.forEach((k, v) -> parsedVars.put(String.valueOf(k), String.valueOf(v)));
            cfg.setVars(parsedVars);
        }

        return cfg;
    }

    private String getString(Map<String, Object> map, String key, String defaultValue) {
        Object v = map.get(key);
        return v != null ? String.valueOf(v) : defaultValue;
    }

    private String stripExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        return dot > 0 ? filename.substring(0, dot) : filename;
    }
}
