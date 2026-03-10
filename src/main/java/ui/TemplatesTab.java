package ui;

import template.ScanTemplate;
import template.TemplateLoader;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * "Templates" tab — shows loaded templates and allows the user to:
 * - See the active templates directory
 * - Reload templates from that directory
 * - Pick a different directory from the filesystem and add its templates
 */
public class TemplatesTab extends JPanel {

    private final TemplateLoader loader;
    private final TemplatesTableModel tableModel = new TemplatesTableModel();
    private final JLabel dirLabel;
    private final JLabel statsLabel;

    public TemplatesTab(TemplateLoader loader) {
        this.loader = loader;
        this.dirLabel = new JLabel();
        this.statsLabel = new JLabel();

        // Listen for reloads triggered from elsewhere
        loader.setOnReload(templates -> SwingUtilities.invokeLater(() -> display(templates)));

        initUI();
        display(loader.loadAll());
    }

    private void initUI() {
        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ---- Top: active directory display + toolbar ----
        JPanel topPanel = new JPanel(new BorderLayout(6, 4));

        JPanel dirPanel = new JPanel(new BorderLayout(6, 0));
        dirPanel.setBorder(BorderFactory.createTitledBorder("Active Templates Directory"));
        dirLabel.setFont(dirLabel.getFont().deriveFont(Font.PLAIN, 12f));
        dirLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        dirPanel.add(dirLabel, BorderLayout.CENTER);
        topPanel.add(dirPanel, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));

        JButton reloadBtn = new JButton("🔄 Reload");
        reloadBtn.setToolTipText("Reload templates from the current directory");
        reloadBtn.addActionListener(e -> {
            List<ScanTemplate> t = loader.reload();
            display(t);
        });

        JButton pickDirBtn = new JButton("📂 Load from folder...");
        pickDirBtn.setToolTipText("Pick any folder and load YAML templates from it into the active set");
        pickDirBtn.addActionListener(e -> pickAndLoadDirectory());

        JButton setDirBtn = new JButton("📌 Set as active directory...");
        setDirBtn.setToolTipText("Change the active templates directory to a new folder (persisted)");
        setDirBtn.addActionListener(e -> pickAndSetDirectory());

        JButton openDirBtn = new JButton("📁 Open in file manager");
        openDirBtn.addActionListener(e -> {
            try {
                Desktop.getDesktop().open(loader.getTemplatesDir().toFile());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Could not open: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        btnPanel.add(reloadBtn);
        btnPanel.add(pickDirBtn);
        btnPanel.add(setDirBtn);
        btnPanel.add(openDirBtn);
        topPanel.add(btnPanel, BorderLayout.SOUTH);

        add(topPanel, BorderLayout.NORTH);

        // ---- Center: templates table ----
        JTable table = new JTable(tableModel);
        table.setRowHeight(22);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(40); // Severity
        table.getColumnModel().getColumn(1).setPreferredWidth(220); // Name
        table.getColumnModel().getColumn(2).setPreferredWidth(80); // Category
        table.getColumnModel().getColumn(3).setPreferredWidth(80); // Payloads
        table.getColumnModel().getColumn(4).setPreferredWidth(150); // Tags
        table.getColumnModel().getColumn(5).setPreferredWidth(200); // Description
        table.setDefaultRenderer(Object.class, new SeverityRenderer());

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createTitledBorder("Loaded Templates"));
        add(scroll, BorderLayout.CENTER);

        // ---- Bottom: stats bar ----
        statsLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        add(statsLabel, BorderLayout.SOUTH);
    }

    private void display(List<ScanTemplate> templates) {
        dirLabel.setText(loader.getTemplatesDir().toString());
        tableModel.setTemplates(templates);

        long highCrit = templates.stream()
                .filter(t -> "high".equals(t.getSeverity()) || "critical".equals(t.getSeverity()))
                .count();
        statsLabel.setText(String.format("  %d templates loaded   •   %d high/critical   •   %d total payloads",
                templates.size(), highCrit,
                templates.stream().mapToInt(t -> t.getPayloads() != null ? t.getPayloads().size() : 0).sum()));
    }

    /**
     * Pick a folder, load templates from it, MERGE into the live list
     * (does not change the active directory).
     */
    private void pickAndLoadDirectory() {
        JFileChooser fc = new JFileChooser(loader.getTemplatesDir().toFile());
        fc.setDialogTitle("Select folder with YAML templates");
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION)
            return;

        Path chosen = fc.getSelectedFile().toPath();
        if (!Files.isDirectory(chosen)) {
            JOptionPane.showMessageDialog(this, "Please select a directory.", "Not a directory",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        List<ScanTemplate> extra = loader.loadFromDirectory(chosen);
        if (extra.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "No valid YAML templates found in:\n" + chosen,
                    "No templates", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Merge into live list (loader exposes the live list via reload, but
        // we want additive here — so we reload current dir first then add)
        List<ScanTemplate> current = new ArrayList<>(loader.loadAll());
        // Deduplicate by ID
        var existingIds = new java.util.HashSet<String>();
        current.forEach(t -> existingIds.add(t.getId()));
        int added = 0;
        for (ScanTemplate t : extra) {
            if (!existingIds.contains(t.getId())) {
                current.add(t);
                added++;
            }
        }

        display(current);
        JOptionPane.showMessageDialog(this,
                String.format("Added %d template(s) from:\n%s", added, chosen),
                "Templates loaded", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Pick a folder and SET it as the new active templates directory.
     * Templates are reloaded from it.
     */
    private void pickAndSetDirectory() {
        JFileChooser fc = new JFileChooser(loader.getTemplatesDir().toFile());
        fc.setDialogTitle("Set active templates directory");
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION)
            return;

        Path chosen = fc.getSelectedFile().toPath();
        if (!Files.isDirectory(chosen)) {
            JOptionPane.showMessageDialog(this, "Please select a directory.", "Not a directory",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        loader.setTemplatesDir(chosen);
        // setTemplatesDir() calls reload() which fires onReload → display()
        JOptionPane.showMessageDialog(this,
                String.format("Active directory changed to:\n%s\n\n%d template(s) loaded.",
                        chosen, loader.loadAll().size()),
                "Directory changed", JOptionPane.INFORMATION_MESSAGE);
    }

    // ---- Table model ---------------------------------------------------

    static class TemplatesTableModel extends AbstractTableModel {
        private static final String[] COLS = { "Sev", "Name", "Category", "Payloads", "Tags", "Description" };
        private List<ScanTemplate> templates = new ArrayList<>();

        void setTemplates(List<ScanTemplate> list) {
            this.templates = new ArrayList<>(list);
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return templates.size();
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
            ScanTemplate t = templates.get(row);
            return switch (col) {
                case 0 -> severityIcon(t.getSeverity());
                case 1 -> t.getName();
                case 2 -> t.getCategory() != null ? t.getCategory() : "";
                case 3 -> t.getPayloads() != null ? t.getPayloads().size() : 0;
                case 4 -> t.getTags() != null ? String.join(", ", t.getTags()) : "";
                case 5 -> t.getDescription() != null ? t.getDescription() : "";
                default -> "";
            };
        }

        private String severityIcon(String sev) {
            if (sev == null)
                return "⚪";
            return switch (sev.toLowerCase()) {
                case "critical" -> "🔴 CRIT";
                case "high" -> "🔴 HIGH";
                case "medium" -> "🟡 MED";
                case "low" -> "🟢 LOW";
                default -> "⚪ INFO";
            };
        }
    }

    static class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                String sev = String.valueOf(table.getValueAt(row, 0)).toLowerCase();
                if (sev.contains("crit") || sev.contains("high"))
                    setBackground(new Color(255, 225, 225));
                else if (sev.contains("med"))
                    setBackground(new Color(255, 252, 220));
                else
                    setBackground(Color.WHITE);
            }
            return this;
        }
    }
}
