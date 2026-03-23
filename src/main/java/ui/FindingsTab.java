package ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import engine.ScanEngine;
import engine.ScanFinding;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

/**
 * Findings tab showing all detected vulnerabilities across all scan jobs.
 * Uses Montoya's native HttpRequestEditor / HttpResponseEditor for
 * displaying original request, baseline, and all payload request/responses.
 */
public class FindingsTab extends JPanel {
    private final ScanEngine scanEngine;
    private final MontoyaApi api;
    private final FindingsTableModel tableModel = new FindingsTableModel();
    private final JTable table;

    // Montoya native editors for the detail pane
    private final HttpRequestEditor baselineRequestEditor;
    private final HttpResponseEditor baselineResponseEditor;

    // Dynamic tabs for payload responses
    private final JTabbedPane detailTabs;
    private final JTabbedPane payloadTabs;

    // Currently displayed payload editors (recreated on each selection)
    private final List<HttpRequestEditor> payloadRequestEditors = new ArrayList<>();
    private final List<HttpResponseEditor> payloadResponseEditors = new ArrayList<>();

    public FindingsTab(ScanEngine scanEngine, MontoyaApi api) {
        this.scanEngine = scanEngine;
        this.api = api;
        this.table = new JTable(tableModel);

        // Create Montoya native editors
        this.baselineRequestEditor = api.userInterface().createHttpRequestEditor(READ_ONLY);
        this.baselineResponseEditor = api.userInterface().createHttpResponseEditor(READ_ONLY);
        this.detailTabs = new JTabbedPane();
        this.payloadTabs = new JTabbedPane();

        initUI();
    }

    private void initUI() {
        setLayout(new BorderLayout(4, 4));

        // ---- Top: Findings table ----
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setMaxWidth(60);   // Severity icon
        table.getColumnModel().getColumn(1).setPreferredWidth(180); // Template
        table.getColumnModel().getColumn(2).setPreferredWidth(200); // Endpoint
        table.getColumnModel().getColumn(3).setPreferredWidth(120); // Param
        table.getColumnModel().getColumn(4).setPreferredWidth(120); // Payload
        table.getColumnModel().getColumn(5).setPreferredWidth(80);  // Rule
        table.getColumnModel().getColumn(6).setPreferredWidth(200); // Trigger
        table.getColumnModel().getColumn(7).setMaxWidth(100);       // Time

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                showDetails(table.getSelectedRow());
            }
        });

        // Color rows by severity
        table.setDefaultRenderer(Object.class, new SeverityCellRenderer());

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Findings"));

        // ---- Bottom: Detail pane with native Burp editors ----
        detailTabs.removeAll();

        // Original / Baseline tab (request + response side-by-side)
        JSplitPane baselineSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                baselineRequestEditor.uiComponent(),
                baselineResponseEditor.uiComponent());
        baselineSplit.setResizeWeight(0.5);
        detailTabs.addTab("Original / Baseline", baselineSplit);

        // Payload responses tab (dynamic — rebuilt when finding is selected)
        detailTabs.addTab("Payload Responses", payloadTabs);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs);
        split.setDividerLocation(250);
        split.setResizeWeight(0.4);
        add(split, BorderLayout.CENTER);

        // ---- Toolbar ----
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton refreshBtn = new JButton("🔄 Refresh");
        refreshBtn.addActionListener(e -> refresh());
        JButton clearBtn = new JButton("🗑 Clear");
        clearBtn.addActionListener(e -> {
            tableModel.clear();
            clearDetailPane();
        });
        toolbar.add(refreshBtn);
        toolbar.add(clearBtn);
        add(toolbar, BorderLayout.NORTH);
    }

    public void refresh() {
        List<ScanFinding> all = new ArrayList<>();
        scanEngine.getAllJobs().forEach(job -> all.addAll(job.getFindings()));
        // Sort by timestamp desc
        all.sort(Comparator.comparingLong(ScanFinding::getTimestamp).reversed());
        tableModel.setFindings(all);
    }

    private void showDetails(int row) {
        ScanFinding f = tableModel.getFinding(row);
        if (f == null) return;

        // 1. Original / Baseline Request
        HttpRequestResponse baseline = f.getBaselineRequestResponse();
        if (baseline != null) {
            baselineRequestEditor.setRequest(baseline.request());
            if (baseline.hasResponse()) {
                baselineResponseEditor.setResponse(baseline.response());
            } else {
                baselineResponseEditor.setResponse(null); // Clear previous if any
            }
        } else if (f.getOriginalRequest() != null) {
            // Fallback if baseline is disabled
            baselineRequestEditor.setRequest(f.getOriginalRequest());
            baselineResponseEditor.setResponse(null);
        }

        // 3. Payload Responses — rebuild dynamic tabs
        clearPayloadTabs();

        LinkedHashMap<String, HttpRequestResponse> responses = f.getPayloadResponses();
        for (Map.Entry<String, HttpRequestResponse> entry : responses.entrySet()) {
            String payloadId = entry.getKey();
            HttpRequestResponse reqResp = entry.getValue();

            HttpRequestEditor reqEditor = api.userInterface().createHttpRequestEditor(READ_ONLY);
            HttpResponseEditor respEditor = api.userInterface().createHttpResponseEditor(READ_ONLY);

            payloadRequestEditors.add(reqEditor);
            payloadResponseEditors.add(respEditor);

            if (reqResp != null) {
                if (reqResp.request() != null) {
                    reqEditor.setRequest(reqResp.request());
                }
                if (reqResp.hasResponse()) {
                    respEditor.setResponse(reqResp.response());
                }
            }

            // Request + Response side-by-side
            JSplitPane pairSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                    reqEditor.uiComponent(), respEditor.uiComponent());
            pairSplit.setResizeWeight(0.5);

            payloadTabs.addTab(payloadId, pairSplit);
        }

        // Auto-switch to Payload Responses tab if there are payloads, else Baseline
        if (!responses.isEmpty()) {
            detailTabs.setSelectedIndex(1);
        } else {
            detailTabs.setSelectedIndex(0);
        }
    }

    private void clearPayloadTabs() {
        payloadTabs.removeAll();
        payloadRequestEditors.clear();
        payloadResponseEditors.clear();
    }

    private void clearDetailPane() {
        clearPayloadTabs();
        // Editors don't have a clear method; they'll be overwritten on next selection
    }

    /** Add a new finding immediately (called from ScanJob listener). */
    public void addFinding(ScanFinding finding) {
        SwingUtilities.invokeLater(() -> tableModel.addFinding(finding));
    }

    // ---- Table model --------------------------------------------------

    static class FindingsTableModel extends AbstractTableModel {
        private static final String[] COLS = { "Sev", "Template", "Endpoint", "Param", "Payload", "Rule", "Trigger", "Time" };
        private final List<ScanFinding> findings = new ArrayList<>();
        private final SimpleDateFormat df = new SimpleDateFormat("HH:mm:ss");

        void setFindings(List<ScanFinding> list) {
            findings.clear();
            findings.addAll(list);
            fireTableDataChanged();
        }

        void addFinding(ScanFinding f) {
            findings.add(0, f);
            fireTableRowsInserted(0, 0);
        }

        void clear() {
            findings.clear();
            fireTableDataChanged();
        }

        ScanFinding getFinding(int row) {
            return row < findings.size() ? findings.get(row) : null;
        }

        @Override
        public int getRowCount() {
            return findings.size();
        }

        @Override
        public int getColumnCount() {
            return COLS.length;
        }

        @Override
        public String getColumnName(int col) {
            return COLS[col];
        }

        @Override
        public Object getValueAt(int row, int col) {
            ScanFinding f = findings.get(row);
            return switch (col) {
                case 0 -> severityIcon(f.getSeverity());
                case 1 -> f.getTemplateName();
                case 2 -> f.getHost() + " " + f.getRoute();
                case 3 -> f.getParamLabel();
                case 4 -> truncate(f.getPayload(), 30);
                case 5 -> f.getMatchedRule() != null ? f.getMatchedRule() : "";
                case 6 -> f.getTriggerReason() != null ? f.getTriggerReason() : "";
                case 7 -> df.format(new Date(f.getTimestamp()));
                default -> "";
            };
        }

        private String severityIcon(String sev) {
            return switch (sev.toLowerCase()) {
                case "critical" -> "🔴 CRIT";
                case "high" -> "🔴 HIGH";
                case "medium" -> "🟡 MED";
                case "low" -> "🟢 LOW";
                default -> "⚪ INFO";
            };
        }

        private String truncate(String s, int max) {
            if (s == null) return "";
            return s.length() > max ? s.substring(0, max) + "..." : s;
        }
    }

    static class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                String sev = String.valueOf(table.getValueAt(row, 0)).toLowerCase();
                if (sev.contains("crit") || sev.contains("high"))
                    setBackground(new Color(255, 220, 220));
                else if (sev.contains("med"))
                    setBackground(new Color(255, 248, 200));
                else
                    setBackground(Color.WHITE);
            }
            return this;
        }
    }
}
