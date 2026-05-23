package burp.ui;

import burp.models.Endpoint;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class EndpointsPanel extends JPanel {

    private static final String[] COLUMNS =
        {"Risk", "Method", "Host", "Path", "Pattern", "Status"};

    private final DefaultTableModel model;
    private final List<Endpoint> endpoints = new ArrayList<>();

    public EndpointsPanel() {
        super(new BorderLayout());

        model = new DefaultTableModel(COLUMNS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(model);
        table.setAutoCreateRowSorter(true);
        table.getRowSorter().toggleSortOrder(0);

        table.getColumnModel().getColumn(0).setPreferredWidth(50);
        table.getColumnModel().getColumn(1).setPreferredWidth(60);
        table.getColumnModel().getColumn(2).setPreferredWidth(160);
        table.getColumnModel().getColumn(3).setPreferredWidth(300);
        table.getColumnModel().getColumn(4).setPreferredWidth(300);
        table.getColumnModel().getColumn(5).setPreferredWidth(60);

        table.setDefaultRenderer(Object.class, new RiskCellRenderer());

        JScrollPane scroll = new JScrollPane(table);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel countLabel = new JLabel("Endpoints: 0");
        JTextField filterField = new JTextField(20);
        filterField.putClientProperty("JTextField.placeholderText", "Filter path...");

        filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(table, filterField.getText()); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(table, filterField.getText()); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) {}
        });

        toolbar.add(new JLabel("Filter:"));
        toolbar.add(filterField);
        toolbar.add(countLabel);

        add(toolbar, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);

        model.addTableModelListener(e ->
            countLabel.setText("Endpoints: " + model.getRowCount())
        );
    }

    public void addEndpoint(Endpoint ep) {
        SwingUtilities.invokeLater(() -> {
            synchronized (endpoints) {
                endpoints.add(ep);
            }
            model.addRow(new Object[]{
                ep.riskScore,
                ep.method,
                ep.host,
                ep.path,
                ep.patternGroup,
                ep.statusCode
            });
        });
    }

    public List<Endpoint> getEndpoints() {
        synchronized (endpoints) {
            return List.copyOf(endpoints);
        }
    }

    private void applyFilter(JTable table, String text) {
        TableRowSorter<?> sorter = (TableRowSorter<?>) table.getRowSorter();
        if (text.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text, 3, 4));
        }
    }

    private static class RiskCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            if (!selected) {
                int risk = (int) table.getValueAt(row, 0);
                if (risk >= 60)      c.setBackground(new Color(255, 200, 200));
                else if (risk >= 30) c.setBackground(new Color(255, 240, 180));
                else                 c.setBackground(Color.WHITE);
            }
            return c;
        }
    }
}
