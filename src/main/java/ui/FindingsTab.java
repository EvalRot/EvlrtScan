package ui;

import engine.ScanEngine;
import engine.ScanFinding;
import engine.ScanJob;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

/**
 * Findings tab showing all detected vulnerabilities across all scan jobs.
 */
public class FindingsTab extends JPanel {
    private final ScanEngine scanEngine;
    private final FindingsTableModel tableModel = new FindingsTableModel();
    private final JTable table;
    private final JTextArea requestArea;
    private final JTextArea responseArea;

    public FindingsTab(ScanEngine scanEngine) {
        this.scanEngine = scanEngine;
        this.table = new JTable(tableModel);
        this.requestArea = makeTextArea();
        this.responseArea = makeTextArea();
        initUI();
    }

    private void initUI() {
        setLayout(new BorderLayout(4, 4));

        // Table
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setMaxWidth(60); // Severity icon
        table.getColumnModel().getColumn(1).setPreferredWidth(180); // Template
        table.getColumnModel().getColumn(2).setPreferredWidth(200); // Endpoint
        table.getColumnModel().getColumn(3).setPreferredWidth(120); // Param
        table.getColumnModel().getColumn(4).setPreferredWidth(120); // Payload
        table.getColumnModel().getColumn(5).setMaxWidth(100); // Time

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                showDetails(table.getSelectedRow());
            }
        });

        // Color rows by severity
        table.setDefaultRenderer(Object.class, new SeverityCellRenderer());

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Findings"));

        // Detail pane — show request + response
        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.addTab("Modified Request", new JScrollPane(requestArea));
        detailTabs.addTab("Response", new JScrollPane(responseArea));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs);
        split.setDividerLocation(250);
        split.setResizeWeight(0.5);
        add(split, BorderLayout.CENTER);

        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton refreshBtn = new JButton("🔄 Refresh");
        refreshBtn.addActionListener(e -> refresh());
        JButton clearBtn = new JButton("🗑 Clear");
        clearBtn.addActionListener(e -> {
            tableModel.clear();
            requestArea.setText("");
            responseArea.setText("");
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
        if (f == null)
            return;

        byte[] req = f.getModifiedRequestBytes();
        byte[] resp = f.getResponseBytes();
        requestArea.setText(req != null ? new String(req) : "(no request)");
        responseArea.setText(resp != null ? new String(resp) : "(no response)");
        requestArea.setCaretPosition(0);
        responseArea.setCaretPosition(0);
    }

    /** Add a new finding immediately (called from ScanJob listener). */
    public void addFinding(ScanFinding finding) {
        SwingUtilities.invokeLater(() -> tableModel.addFinding(finding));
    }

    private JTextArea makeTextArea() {
        JTextArea ta = new JTextArea();
        ta.setEditable(false);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        ta.setMargin(new Insets(4, 4, 4, 4));
        return ta;
    }

    // ---- Table model --------------------------------------------------

    static class FindingsTableModel extends AbstractTableModel {
        private static final String[] COLS = { "Sev", "Template", "Endpoint", "Param", "Payload", "Time" };
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
                case 5 -> df.format(new Date(f.getTimestamp()));
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
            if (s == null)
                return "";
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
