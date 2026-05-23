package burp.ui;

import burp.models.CveEntry;
import burp.models.Technology;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class TechStackPanel extends JPanel {

    private static final String[] COLUMNS =
        {"Severity", "Technology", "Version", "Category", "CVEs", "Confidence", "Host"};

    private final DefaultTableModel model;
    private final List<Technology> technologies = new ArrayList<>();
    private final JTextArea cveDetail;

    public TechStackPanel() {
        super(new BorderLayout());

        model = new DefaultTableModel(COLUMNS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        // domyślnie sortuj po Severity (col 0) malejąco
        ((TableRowSorter<?>) table.getRowSorter()).toggleSortOrder(0);

        // szerokości kolumn
        table.getColumnModel().getColumn(0).setPreferredWidth(70);   // Severity
        table.getColumnModel().getColumn(1).setPreferredWidth(130);  // Technology
        table.getColumnModel().getColumn(2).setPreferredWidth(80);   // Version
        table.getColumnModel().getColumn(3).setPreferredWidth(120);  // Category
        table.getColumnModel().getColumn(4).setPreferredWidth(40);   // CVEs count
        table.getColumnModel().getColumn(5).setPreferredWidth(80);   // Confidence
        table.getColumnModel().getColumn(6).setPreferredWidth(180);  // Host

        table.setDefaultRenderer(Object.class, new SeverityCellRenderer());

        // panel szczegółów CVE — pojawia się po kliknięciu wiersza
        cveDetail = new JTextArea(5, 40);
        cveDetail.setEditable(false);
        cveDetail.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) return;
            int modelRow = table.convertRowIndexToModel(viewRow);
            showCveDetail(technologies.get(modelRow));
        });

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel countLabel = new JLabel("Technologies: 0");
        toolbar.add(countLabel);

        model.addTableModelListener(e ->
            countLabel.setText("Technologies: " + model.getRowCount())
        );

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(table),
            new JScrollPane(cveDetail));
        split.setResizeWeight(0.75);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    public void addTechnology(Technology tech) {
        SwingUtilities.invokeLater(() -> {
            technologies.add(tech);
            model.addRow(new Object[]{
                tech.highestSeverity(),
                tech.name,
                tech.version != null ? tech.version : "—",
                tech.category,
                tech.cves.size(),
                tech.confidence + "%",
                tech.host
            });
        });
    }

    private void showCveDetail(Technology tech) {
        if (tech.cves.isEmpty()) {
            cveDetail.setText("No CVEs found for " + tech.name +
                (tech.version != null ? " " + tech.version : "") + ".");
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (CveEntry cve : tech.cves) {
            sb.append(cve.cve_id)
              .append("  [").append(cve.severity).append("]")
              .append("  CVSS: ").append(cve.cvss).append("\n")
              .append(cve.description).append("\n\n");
        }
        cveDetail.setText(sb.toString().trim());
        cveDetail.setCaretPosition(0);
    }

    // koloruje wiersze wg severity
    private static class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            if (!selected) {
                String sev = (String) table.getValueAt(row, 0);
                Color bg = Color.WHITE;
                if ("CRITICAL".equals(sev)) bg = new Color(255, 180, 180);
                else if ("HIGH".equals(sev)) bg = new Color(255, 210, 170);
                else if ("MEDIUM".equals(sev)) bg = new Color(255, 240, 180);
                else if ("LOW".equals(sev)) bg = new Color(220, 240, 220);
                c.setBackground(bg);
            }
            return c;
        }
    }
}
