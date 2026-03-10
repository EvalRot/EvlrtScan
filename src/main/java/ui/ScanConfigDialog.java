package ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import engine.*;
import engine.EncodingDetector.Encoding;
import template.ScanTemplate;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.*;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Modal dialog that appears when the user triggers a scan.
 * Shows parsed insertion points (as a sortable table with encoding info),
 * available templates, and per-scan options.
 */
public class ScanConfigDialog extends JDialog {
    private final HttpRequest request;
    private final List<ScanTemplate> templates;
    private final List<InsertionPoint> points;
    private final ScanEngine scanEngine;

    // Table model for insertion points
    private InsertionPointTableModel pointsTableModel;
    private JTable pointsTable;

    // Checkboxes for templates
    private final Map<ScanTemplate, JCheckBox> templateBoxes = new LinkedHashMap<>();

    // Options
    private JSpinner threadsSpinner;
    private JSpinner delaySpinner;
    private JSpinner timeoutSpinner;
    private JLabel summaryLabel;

    // Pre-computed encodings
    private final Map<InsertionPoint, Encoding> detectedEncodings = new LinkedHashMap<>();

    public ScanConfigDialog(Window parent, HttpRequest request, List<ScanTemplate> templates,
            List<InsertionPoint> points, ScanEngine scanEngine) {
        super(parent, "\uD83D\uDD2B Quickfire — Scan Configuration", ModalityType.APPLICATION_MODAL);
        this.request = request;
        this.templates = templates;
        this.points = points;
        this.scanEngine = scanEngine;

        // Pre-detect encodings for all insertion points
        for (InsertionPoint pt : points) {
            detectedEncodings.put(pt, EncodingDetector.detect(pt.getOriginalValue()));
        }

        setSize(800, 750);
        setLocationRelativeTo(parent);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        initUI();
    }

    private void initUI() {
        setLayout(new BorderLayout(8, 8));
        getRootPane().setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Target label at top
        JLabel targetLabel = new JLabel("Target: " + request.method() + " "
                + request.httpService().host() + request.path());
        targetLabel.setFont(targetLabel.getFont().deriveFont(Font.BOLD));
        add(targetLabel, BorderLayout.NORTH);

        // Center: split between insertion points table and templates
        JSplitPane center = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                buildInsertionPointsPanel(), buildTemplatesPanel());
        center.setDividerLocation(300);
        center.setResizeWeight(0.5);
        add(center, BorderLayout.CENTER);

        // Bottom: options + summary + buttons
        add(buildBottomPanel(), BorderLayout.SOUTH);
        updateSummary();
    }

    // ---- Insertion Points Table ----------------------------------------

    private JPanel buildInsertionPointsPanel() {
        JPanel wrapper = new JPanel(new BorderLayout(4, 4));
        wrapper.setBorder(new TitledBorder("Insertion Points"));

        // Quick buttons
        JPanel quickPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton selectAll = new JButton("Select All");
        selectAll.addActionListener(e -> {
            pointsTableModel.setAllSelected(true);
            updateSummary();
        });
        JButton deselectAll = new JButton("Deselect All");
        deselectAll.addActionListener(e -> {
            pointsTableModel.setAllSelected(false);
            updateSummary();
        });
        JButton paramsOnly = new JButton("Params Only");
        paramsOnly.addActionListener(e -> {
            pointsTableModel.selectParamsOnly();
            updateSummary();
        });
        quickPanel.add(selectAll);
        quickPanel.add(deselectAll);
        quickPanel.add(paramsOnly);
        wrapper.add(quickPanel, BorderLayout.NORTH);

        // Build table model
        pointsTableModel = new InsertionPointTableModel(points, detectedEncodings);
        pointsTable = new JTable(pointsTableModel);
        pointsTable.setRowHeight(22);
        pointsTable.setAutoCreateRowSorter(true);
        pointsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Column widths
        pointsTable.getColumnModel().getColumn(0).setMaxWidth(35); // Checkbox
        pointsTable.getColumnModel().getColumn(0).setMinWidth(35);
        pointsTable.getColumnModel().getColumn(1).setPreferredWidth(120); // Type
        pointsTable.getColumnModel().getColumn(2).setPreferredWidth(150); // Name
        pointsTable.getColumnModel().getColumn(3).setPreferredWidth(200); // Value
        pointsTable.getColumnModel().getColumn(4).setPreferredWidth(110); // Encoding

        // Custom renderer for type column
        pointsTable.getColumnModel().getColumn(1).setCellRenderer(new TypeCellRenderer());
        // Custom renderer for encoding column
        pointsTable.getColumnModel().getColumn(4).setCellRenderer(new EncodingCellRenderer());

        // Listen for checkbox changes
        pointsTableModel.addTableModelListener(e -> updateSummary());

        if (points.isEmpty()) {
            wrapper.add(new JLabel("  No insertion points detected in this request."),
                    BorderLayout.CENTER);
        } else {
            wrapper.add(new JScrollPane(pointsTable), BorderLayout.CENTER);
        }

        return wrapper;
    }

    // ---- Templates Panel -----------------------------------------------

    private JScrollPane buildTemplatesPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JPanel quickPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        addTemplateQuickButton(quickPanel, "Select All", true);
        addTemplateQuickButton(quickPanel, "Deselect All", false);
        panel.add(quickPanel);

        if (templates.isEmpty()) {
            panel.add(new JLabel("  No templates loaded. Check templates directory."));
        }

        // Group by category
        Map<String, List<ScanTemplate>> byCategory = new LinkedHashMap<>();
        for (ScanTemplate t : templates) {
            byCategory.computeIfAbsent(t.getCategory() != null ? t.getCategory() : "other",
                    c -> new ArrayList<>()).add(t);
        }

        byCategory.forEach((cat, tmplList) -> {
            JLabel catLabel = new JLabel("  " + cat.toUpperCase() + ":");
            catLabel.setFont(catLabel.getFont().deriveFont(Font.BOLD, 11f));
            catLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
            panel.add(catLabel);

            for (ScanTemplate t : tmplList) {
                String label = String.format("%-40s  [%s]  %s",
                        t.getName(),
                        t.getTags() != null ? String.join(", ", t.getTags()) : "",
                        t.getSeverity().toUpperCase());
                JCheckBox cb = new JCheckBox(label);
                cb.setSelected(true);
                cb.addItemListener(e -> updateSummary());
                cb.setBorder(BorderFactory.createEmptyBorder(0, 16, 0, 0));
                cb.setAlignmentX(Component.LEFT_ALIGNMENT);
                templateBoxes.put(t, cb);
                panel.add(cb);
            }
        });

        JScrollPane scroll = new JScrollPane(panel);
        scroll.setBorder(new TitledBorder("Templates"));
        return scroll;
    }

    // ---- Bottom Panel --------------------------------------------------

    private JPanel buildBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));

        JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        opts.setBorder(new TitledBorder("Options"));

        threadsSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 50, 1));
        delaySpinner = new JSpinner(new SpinnerNumberModel(100, 0, 10000, 50));
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(15, 1, 120, 1));

        opts.add(new JLabel("Threads:"));
        opts.add(threadsSpinner);
        opts.add(new JLabel("Delay (ms):"));
        opts.add(delaySpinner);
        opts.add(new JLabel("Timeout (s):"));
        opts.add(timeoutSpinner);

        summaryLabel = new JLabel("Select templates and insertion points...");
        summaryLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
        JButton cancelBtn = new JButton("Cancel");
        cancelBtn.addActionListener(e -> dispose());
        JButton startBtn = new JButton("▶ Start Scan");
        startBtn.setFont(startBtn.getFont().deriveFont(Font.BOLD));
        startBtn.addActionListener(e -> startScan());
        buttons.add(cancelBtn);
        buttons.add(startBtn);

        panel.add(opts, BorderLayout.NORTH);
        panel.add(summaryLabel, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    // ---- Actions -------------------------------------------------------

    private void startScan() {
        List<InsertionPoint> selectedPoints = pointsTableModel.getSelectedPoints();

        List<ScanTemplate> selectedTemplates = new ArrayList<>();
        templateBoxes.forEach((t, cb) -> {
            if (cb.isSelected())
                selectedTemplates.add(t);
        });

        if (selectedPoints.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Select at least one insertion point.",
                    "No selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (selectedTemplates.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Select at least one template.",
                    "No selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        ScanOptions opts = new ScanOptions(
                (Integer) threadsSpinner.getValue(),
                (Integer) delaySpinner.getValue(),
                (Integer) timeoutSpinner.getValue(),
                false, true);

        dispose();
        scanEngine.submitJob(request, selectedTemplates, selectedPoints, opts);
    }

    private void updateSummary() {
        long selPoints = pointsTableModel != null ? pointsTableModel.getSelectedPoints().size() : 0;
        long selTemplates = templateBoxes.values().stream().filter(AbstractButton::isSelected).count();
        long totalPayloads = templateBoxes.entrySet().stream()
                .filter(e -> e.getValue().isSelected())
                .mapToLong(e -> e.getKey().getPayloads().size())
                .sum();
        long estimated = selPoints * totalPayloads;
        summaryLabel.setText(String.format("%d params × %d templates × ~%d payloads = ~%d requests",
                selPoints, selTemplates, totalPayloads, estimated));
    }

    private void addTemplateQuickButton(JPanel panel, String label, boolean select) {
        JButton btn = new JButton(label);
        btn.addActionListener(e -> {
            templateBoxes.values().forEach(cb -> cb.setSelected(select));
            updateSummary();
        });
        panel.add(btn);
    }

    // ---- Table Model ---------------------------------------------------

    static class InsertionPointTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = { "✓", "Type", "Name", "Value", "Encoding" };
        private final List<InsertionPoint> points;
        private final Map<InsertionPoint, Encoding> encodings;
        private final boolean[] selected;

        InsertionPointTableModel(List<InsertionPoint> points, Map<InsertionPoint, Encoding> encodings) {
            this.points = new ArrayList<>(points);
            this.encodings = encodings;
            this.selected = new boolean[points.size()];
            // Auto-select params by default
            for (int i = 0; i < points.size(); i++) {
                InsertionPoint.Type t = points.get(i).getType();
                selected[i] = (t == InsertionPoint.Type.QUERY_PARAM
                        || t == InsertionPoint.Type.BODY_PARAM
                        || t == InsertionPoint.Type.JSON_VALUE);
            }
        }

        @Override
        public int getRowCount() {
            return points.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int col) {
            return COLUMNS[col];
        }

        @Override
        public Class<?> getColumnClass(int col) {
            return col == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int row, int col) {
            return col == 0; // Only checkbox is editable
        }

        @Override
        public Object getValueAt(int row, int col) {
            InsertionPoint pt = points.get(row);
            return switch (col) {
                case 0 -> selected[row];
                case 1 -> typeLabel(pt.getType());
                case 2 -> pt.getName();
                case 3 -> truncate(pt.getOriginalValue(), 60);
                case 4 -> encodingLabel(encodings.getOrDefault(pt, Encoding.PLAIN));
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object val, int row, int col) {
            if (col == 0) {
                selected[row] = (Boolean) val;
                fireTableCellUpdated(row, col);
            }
        }

        void setAllSelected(boolean sel) {
            for (int i = 0; i < selected.length; i++)
                selected[i] = sel;
            fireTableDataChanged();
        }

        void selectParamsOnly() {
            for (int i = 0; i < points.size(); i++) {
                InsertionPoint.Type t = points.get(i).getType();
                selected[i] = (t == InsertionPoint.Type.QUERY_PARAM
                        || t == InsertionPoint.Type.BODY_PARAM
                        || t == InsertionPoint.Type.JSON_VALUE);
            }
            fireTableDataChanged();
        }

        List<InsertionPoint> getSelectedPoints() {
            List<InsertionPoint> sel = new ArrayList<>();
            for (int i = 0; i < points.size(); i++) {
                if (selected[i])
                    sel.add(points.get(i));
            }
            return sel;
        }

        private static String typeLabel(InsertionPoint.Type type) {
            return switch (type) {
                case QUERY_PARAM -> "GET";
                case BODY_PARAM -> "POST URL-encoded";
                case JSON_VALUE -> "JSON";
                case XML_VALUE -> "XML";
                case COOKIE -> "Cookie";
                case HEADER -> "Header";
                case URL_PATH_SEGMENT -> "URL Path";
            };
        }

        private static String encodingLabel(Encoding enc) {
            return switch (enc) {
                case PLAIN -> "Plain text";
                case URL_ENCODED -> "URL-encoded";
                case BASE64 -> "Base64";
                case BASE64_URL_ENCODED -> "Base64 + URL";
                case UNICODE -> "Unicode";
            };
        }

        private static String truncate(String s, int max) {
            if (s == null)
                return "";
            return s.length() <= max ? s : s.substring(0, max) + "…";
        }
    }

    // ---- Cell Renderers ------------------------------------------------

    static class TypeCellRenderer extends DefaultTableCellRenderer {
        private static final Map<String, Color> TYPE_COLORS = Map.of(
                "GET", new Color(52, 152, 219),
                "POST URL-encoded", new Color(231, 76, 60),
                "JSON", new Color(46, 204, 113),
                "Cookie", new Color(155, 89, 182),
                "Header", new Color(149, 165, 166),
                "URL Path", new Color(243, 156, 18),
                "XML", new Color(26, 188, 156));

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int col) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            setFont(getFont().deriveFont(Font.BOLD, 11f));
            if (!isSelected) {
                String type = String.valueOf(value);
                setForeground(TYPE_COLORS.getOrDefault(type, Color.DARK_GRAY));
            }
            return this;
        }
    }

    static class EncodingCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int col) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            setFont(getFont().deriveFont(Font.ITALIC, 11f));
            if (!isSelected) {
                String enc = String.valueOf(value);
                if (enc.contains("Base64") || enc.contains("URL"))
                    setForeground(new Color(192, 57, 43));
                else if (enc.contains("Unicode"))
                    setForeground(new Color(142, 68, 173));
                else
                    setForeground(Color.GRAY);
            }
            return this;
        }
    }
}
