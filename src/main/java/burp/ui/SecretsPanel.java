package burp.ui;

import burp.models.Secret;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class SecretsPanel extends JPanel {

    private static final String[] COLUMNS =
        {"Severity", "Type", "Value", "Entropy", "Detected By", "Host", "URL"};

    private final DefaultTableModel model;
    private final List<Secret> secrets = new ArrayList<>();
    private final JTextArea contextArea;

    public SecretsPanel() {
        super(new BorderLayout());

        model = new DefaultTableModel(COLUMNS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(model);
        table.setAutoCreateRowSorter(true);

        // szerokości kolumn
        table.getColumnModel().getColumn(0).setPreferredWidth(70);   // Severity
        table.getColumnModel().getColumn(1).setPreferredWidth(180);  // Type
        table.getColumnModel().getColumn(2).setPreferredWidth(160);  // Value (redacted)
        table.getColumnModel().getColumn(3).setPreferredWidth(60);   // Entropy
        table.getColumnModel().getColumn(4).setPreferredWidth(80);   // Detected By
        table.getColumnModel().getColumn(5).setPreferredWidth(150);  // Host
        table.getColumnModel().getColumn(6).setPreferredWidth(200);  // URL

        table.setDefaultRenderer(Object.class, new SeverityCellRenderer());

        // panel dolny — kontekst + pełna wartość po kliknięciu
        contextArea = new JTextArea(6, 60);
        contextArea.setEditable(false);
        contextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        contextArea.setLineWrap(true);
        contextArea.setWrapStyleWord(false);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) return;
            int modelRow = table.convertRowIndexToModel(viewRow);
            showDetail(secrets.get(modelRow));
        });

        // toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel countLabel = new JLabel("Secrets: 0");
        JTextField filterField = new JTextField(20);
        filterField.putClientProperty("JTextField.placeholderText", "Filter by type or host...");

        filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filter(table, filterField.getText()); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filter(table, filterField.getText()); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) {}
        });

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.addActionListener(e -> exportCsv());

        toolbar.add(new JLabel("Filter:"));
        toolbar.add(filterField);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(countLabel);
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(exportBtn);

        model.addTableModelListener(e ->
            countLabel.setText("Secrets: " + model.getRowCount())
        );

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(table),
            new JScrollPane(contextArea));
        split.setResizeWeight(0.65);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    public void addSecret(Secret secret) {
        SwingUtilities.invokeLater(() -> {
            synchronized (secrets) {
                secrets.add(secret);
            }
            model.addRow(new Object[]{
                secret.severity,
                secret.type,
                secret.value,
                String.format("%.2f", secret.entropy),
                secret.detectedBy,
                secret.host,
                truncateUrl(secret.url)
            });
        });
    }

    public List<Secret> getSecrets() {
        synchronized (secrets) {
            return List.copyOf(secrets);
        }
    }

    private void showDetail(Secret s) {
        contextArea.setText(
            "Type:      " + s.type + "\n" +
            "Severity:  " + s.severity + "\n" +
            "Entropy:   " + String.format("%.3f", s.entropy) + "\n" +
            "Full value: " + s.fullValue + "\n" +
            "URL:       " + s.url + "\n\n" +
            "Context:\n" + s.context
        );
        contextArea.setCaretPosition(0);
    }

    private void filter(JTable table, String text) {
        TableRowSorter<?> sorter = (TableRowSorter<?>) table.getRowSorter();
        sorter.setRowFilter(text.isEmpty() ? null
            : RowFilter.regexFilter("(?i)" + text, 0, 1, 5, 6));
    }

    private void exportCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("secrets-export.csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try (java.io.PrintWriter pw = new java.io.PrintWriter(fc.getSelectedFile(), "UTF-8")) {
            pw.println("severity,type,value,entropy,host,url");
            for (Secret s : secrets) {
                pw.printf("\"%s\",\"%s\",\"%s\",\"%.2f\",\"%s\",\"%s\"%n",
                    s.severity, s.type, s.value, s.entropy, s.host, s.url);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage());
        }
    }

    private String truncateUrl(String url) {
        return url != null && url.length() > 80 ? url.substring(0, 77) + "..." : url;
    }

    // kolorowanie identyczne jak w TechStackPanel — CRITICAL/HIGH/MEDIUM/LOW
    private static class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            if (!selected) {
                String sev = (String) table.getValueAt(row, 0);
                Color bg = Color.WHITE;
                if ("CRITICAL".equals(sev)) {
                    bg = new Color(255, 160, 160);
                } else if ("HIGH".equals(sev)) {
                    bg = new Color(255, 200, 150);
                } else if ("MEDIUM".equals(sev)) {
                    bg = new Color(255, 240, 170);
                } else if ("LOW".equals(sev)) {
                    bg = new Color(210, 235, 210);
                }
                c.setBackground(bg);
            }
            return c;
        }
    }
}
