package ui;

import coverage.CoverageTracker;
import coverage.EndpointRecord;
import handler.TrafficFilter;

import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * The Coverage Map tab — shows a tree of all known endpoints with scan status.
 * Includes a filter bar to control which requests are recorded from proxy
 * traffic.
 */
public class CoverageTab extends JPanel {
    private final CoverageTracker tracker;
    private final TrafficFilter filter;

    private final DefaultTreeModel treeModel;
    private final DefaultMutableTreeNode root;
    private final JTree tree;
    private final JTextArea detailArea;
    private final JLabel statsLabel;

    // Filter widgets
    private JCheckBox scopeOnlyBox;
    private JTextField excludedMethodsField;

    // Known HTTP method toggle checkboxes (quick-click)
    private static final String[] COMMON_METHODS = { "OPTIONS", "HEAD", "TRACE", "CONNECT", "GET", "POST", "PUT",
            "DELETE", "PATCH" };

    public CoverageTab(CoverageTracker tracker, TrafficFilter filter) {
        this.tracker = tracker;
        this.filter = filter;
        this.root = new DefaultMutableTreeNode("Coverage Map");
        this.treeModel = new DefaultTreeModel(root);
        this.tree = new JTree(treeModel);
        this.detailArea = new JTextArea();
        this.statsLabel = new JLabel(" Loading...");

        tracker.setChangeListener(v -> SwingUtilities.invokeLater(this::refresh));
        initUI();
        refresh();
    }

    private void initUI() {
        setLayout(new BorderLayout(4, 4));

        // ---- Top panel = filter bar + action toolbar ----
        JPanel topPanel = new JPanel(new BorderLayout(0, 4));
        topPanel.add(buildFilterBar(), BorderLayout.NORTH);
        topPanel.add(buildActionToolbar(), BorderLayout.SOUTH);
        add(topPanel, BorderLayout.NORTH);

        // ---- Tree + detail split ----
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.setCellRenderer(new CoverageTreeCellRenderer());
        tree.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                TreePath path = tree.getPathForLocation(e.getX(), e.getY());
                if (path != null)
                    showDetails(path);
            }
        });

        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setMargin(new Insets(8, 8, 8, 8));

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(tree), new JScrollPane(detailArea));
        splitPane.setDividerLocation(300);
        splitPane.setResizeWeight(0.4);
        add(splitPane, BorderLayout.CENTER);

        // ---- Stats bar at bottom ----
        statsLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        add(statsLabel, BorderLayout.SOUTH);
    }

    private JPanel buildFilterBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBorder(BorderFactory.createTitledBorder("Proxy Traffic Filter"));

        // ---- Scope only ----
        scopeOnlyBox = new JCheckBox("In-scope only", filter.isScopeOnly());
        scopeOnlyBox.setToolTipText("Record only requests that are in Burp's Target scope");
        scopeOnlyBox.addItemListener(e -> {
            filter.setScopeOnly(scopeOnlyBox.isSelected());
        });
        bar.add(scopeOnlyBox);

        bar.add(new JSeparator(JSeparator.VERTICAL));
        bar.add(new JLabel("Exclude methods:"));

        // ---- Per-method toggle checkboxes ----
        for (String method : COMMON_METHODS) {
            boolean isExcluded = filter.getExcludedMethods().contains(method);
            JCheckBox cb = new JCheckBox(method, isExcluded);
            cb.setFont(cb.getFont().deriveFont(Font.PLAIN, 11f));
            cb.addItemListener(e -> {
                if (cb.isSelected()) {
                    filter.addExcludedMethod(method);
                } else {
                    filter.removeExcludedMethod(method);
                }
                syncExcludedField();
            });
            styleMethodCheckbox(cb, method);
            bar.add(cb);
        }

        bar.add(new JSeparator(JSeparator.VERTICAL));

        // ---- Custom methods text field ----
        bar.add(new JLabel("Custom:"));
        excludedMethodsField = new JTextField(buildExcludedString(), 14);
        excludedMethodsField.setToolTipText("Comma-separated additional methods to exclude (e.g. PROPFIND, LOCK)");
        excludedMethodsField.setFont(excludedMethodsField.getFont().deriveFont(Font.PLAIN, 11f));
        excludedMethodsField.addActionListener(e -> applyCustomMethods());
        bar.add(excludedMethodsField);

        JButton applyBtn = new JButton("Apply");
        applyBtn.setFont(applyBtn.getFont().deriveFont(11f));
        applyBtn.addActionListener(e -> applyCustomMethods());
        bar.add(applyBtn);

        return bar;
    }

    private JPanel buildActionToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        JButton refreshBtn = new JButton("🔄 Refresh");
        refreshBtn.addActionListener(e -> refresh());

        JButton exportBtn = new JButton("📤 Export JSON...");
        exportBtn.addActionListener(e -> exportCoverage());

        JButton importBtn = new JButton("📥 Import JSON...");
        importBtn.addActionListener(e -> importCoverage());

        JButton clearBtn = new JButton("🗑 Clear All");
        clearBtn.setToolTipText("Remove all coverage data (cannot be undone)");
        clearBtn.addActionListener(e -> {
            int ok = JOptionPane.showConfirmDialog(this,
                    "Clear all coverage data?", "Confirm", JOptionPane.YES_NO_OPTION);
            if (ok == JOptionPane.YES_OPTION) {
                tracker.clearAll();
            }
        });

        toolbar.add(refreshBtn);
        toolbar.add(exportBtn);
        toolbar.add(importBtn);
        toolbar.add(clearBtn);
        return toolbar;
    }

    private void styleMethodCheckbox(JCheckBox cb, String method) {
        // Visually distinguish noise methods vs useful ones
        boolean isNoise = Set.of("OPTIONS", "HEAD", "TRACE", "CONNECT").contains(method);
        if (isNoise && cb.isSelected()) {
            cb.setForeground(new Color(160, 80, 80));
        }
        cb.addItemListener(e -> {
            if (isNoise && cb.isSelected())
                cb.setForeground(new Color(160, 80, 80));
            else
                cb.setForeground(UIManager.getColor("CheckBox.foreground"));
        });
    }

    private void syncExcludedField() {
        excludedMethodsField.setText(buildExcludedString());
    }

    private String buildExcludedString() {
        // Only show methods NOT in COMMON_METHODS (those are shown as checkboxes)
        var common = Set.of(COMMON_METHODS);
        var extras = filter.getExcludedMethods().stream()
                .filter(m -> !common.contains(m))
                .sorted()
                .toList();
        return String.join(", ", extras);
    }

    private void applyCustomMethods() {
        String raw = excludedMethodsField.getText();
        // Keep current checkbox-controlled methods, add custom ones
        var common = Set.of(COMMON_METHODS);
        // Remove all non-common exclusions first
        filter.getExcludedMethods().stream()
                .filter(m -> !common.contains(m))
                .toList()
                .forEach(filter::removeExcludedMethod);

        // Add back whatever is in the text field
        for (String part : raw.split("[,\\s]+")) {
            String m = part.trim().toUpperCase();
            if (!m.isEmpty())
                filter.addExcludedMethod(m);
        }
    }

    // ---- Tree refresh --------------------------------------------------

    public void refresh() {
        root.removeAllChildren();
        var all = tracker.getAll();
        int total = 0, fullScanned = 0, partial = 0;

        for (Map.Entry<String, Map<String, EndpointRecord>> hostEntry : all.entrySet()) {
            DefaultMutableTreeNode hostNode = new DefaultMutableTreeNode(
                    new NodeData(hostEntry.getKey(), null, NodeData.NodeType.HOST));
            root.add(hostNode);

            for (Map.Entry<String, EndpointRecord> routeEntry : hostEntry.getValue().entrySet()) {
                EndpointRecord record = routeEntry.getValue();
                EndpointRecord.ScanStatus status = record.getScanStatus(java.util.List.of());

                DefaultMutableTreeNode routeNode = new DefaultMutableTreeNode(
                        new NodeData(routeEntry.getKey(), record, NodeData.NodeType.ROUTE));
                hostNode.add(routeNode);
                total++;
                if (status == EndpointRecord.ScanStatus.FULL)
                    fullScanned++;
                else if (status == EndpointRecord.ScanStatus.PARTIAL)
                    partial++;
            }
        }

        treeModel.reload();
        // Expand all host nodes
        for (int i = 0; i < root.getChildCount(); i++) {
            tree.expandPath(new TreePath(
                    ((DefaultMutableTreeNode) root.getChildAt(i)).getPath()));
        }

        int notScanned = total - fullScanned - partial;
        statsLabel.setText(String.format(
                "  %d endpoints   ✅ %d full   ⚠ %d partial   ⛔ %d not scanned   %s",
                total, fullScanned, partial, notScanned,
                filter.isScopeOnly() ? "  🎯 scope only" : "  🌐 all traffic"));
    }

    // ---- Detail pane ---------------------------------------------------

    private void showDetails(TreePath path) {
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
        if (!(node.getUserObject() instanceof NodeData nd))
            return;
        if (nd.type == NodeData.NodeType.HOST) {
            detailArea.setText("Host: " + nd.label + "\nRoutes: " + node.getChildCount());
            return;
        }

        EndpointRecord rec = nd.record;
        if (rec == null)
            return;

        StringBuilder sb = new StringBuilder();
        sb.append("Endpoint: ").append(rec.getRouteKey()).append("\n");
        sb.append("Host:     ").append(rec.getHost()).append("\n");
        sb.append("Source:   ").append(rec.getSource()).append("\n");
        sb.append("First seen: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm").format(
                new Date(rec.getFirstSeen()))).append("\n");
        sb.append("\nScan History:\n");

        if (rec.getTemplateScans().isEmpty()) {
            sb.append("  (not scanned yet)\n");
        } else {
            var fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            rec.getTemplateScans().forEach(ts -> {
                String icon = "completed".equals(ts.getStatus()) ? "✅" : "⚠";
                String params = ts.getScannedParams() != null && !ts.getScannedParams().isEmpty()
                        ? String.join(", ", ts.getScannedParams()) : "-";
                sb.append(String.format("  %s %-30s  findings: %d  params: [%s]  %s\n",
                        icon, ts.getTemplateId(), ts.getFindings(), params,
                        fmt.format(new Date(ts.getTimestamp()))));
            });
        }

        sb.append("\nFindings: ").append(rec.getTotalFindingCount());
        rec.getFindings().forEach(f -> {
            String scores = f.getDiffScores() != null && !f.getDiffScores().isEmpty() 
                ? "  =>  " + f.getDiffScores() 
                : "";
            sb.append(String.format("\n  [%s] %s in %s (payload: %s)%s",
                    f.getSeverity().toUpperCase(), f.getTemplateName(),
                    f.getParamLabel(), f.getPayload(), scores));
        });

        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    // ---- Export / Import -----------------------------------------------

    private void exportCoverage() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("evlrtscan-coverage.json"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                tracker.exportToFile(fc.getSelectedFile());
                JOptionPane.showMessageDialog(this, "Coverage exported successfully.");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importCoverage() {
        JFileChooser fc = new JFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                tracker.importFromFile(fc.getSelectedFile());
                JOptionPane.showMessageDialog(this, "Coverage imported and merged successfully.");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // ---- Inner classes -------------------------------------------------

    record NodeData(String label, EndpointRecord record, NodeType type) {
        enum NodeType {
            HOST, ROUTE
        }
    }

    static class CoverageTreeCellRenderer extends DefaultTreeCellRenderer {
        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel,
                boolean expanded, boolean leaf, int row, boolean hasFocus) {
            super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
            if (value instanceof DefaultMutableTreeNode node
                    && node.getUserObject() instanceof NodeData nd) {
                if (nd.type == NodeData.NodeType.HOST) {
                    setText("🌐 " + nd.label);
                } else if (nd.record != null) {
                    EndpointRecord.ScanStatus status = nd.record.getScanStatus(java.util.List.of());
                    String icon = switch (status) {
                        case FULL -> "✅";
                        case PARTIAL -> "⚠";
                        case NOT_SCANNED -> "⛔";
                    };
                    String findings = nd.record.getTotalFindingCount() > 0
                            ? " 🔴 " + nd.record.getTotalFindingCount()
                            : "";
                    setText(icon + " " + nd.label + findings);
                }
            }
            return this;
        }
    }
}
