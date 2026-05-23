package burp.ui;

import burp.BurpExtender;
import burp.models.Endpoint;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class EndpointsPanel extends JPanel implements IMessageEditorController {

    private static final String[] COLUMNS =
        {"Risk", "Method", "Host", "Path", "Pattern", "Status"};

    private final DefaultTableModel model;
    private final List<Endpoint> endpoints = new ArrayList<>();
    private IHttpRequestResponse currentlySelectedMessage;
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;

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

        burp.ui.utils.ContextMenuFactory.addContextMenu(table,
            row -> {
                synchronized (endpoints) {
                    if (row >= 0 && row < endpoints.size()) {
                        return endpoints.get(row).originalRequestResponse;
                    }
                }
                return null;
            },
            row -> {
                synchronized (endpoints) {
                    if (row >= 0 && row < endpoints.size()) {
                        Endpoint ep = endpoints.get(row);
                        if (ep.originalRequestResponse != null && ep.originalRequestResponse.getHttpService() != null) {
                            try {
                                return BurpExtender.helpers.analyzeRequest(ep.originalRequestResponse).getUrl().toString();
                            } catch (Exception ignored) {}
                        }
                        String proto = "https";
                        return proto + "://" + ep.host + ep.path;
                    }
                }
                return null;
            }
        );

        JScrollPane scroll = new JScrollPane(table);

        // Native Burp Message Editors
        requestEditor = BurpExtender.callbacks.createMessageEditor(this, false);
        responseEditor = BurpExtender.callbacks.createMessageEditor(this, false);

        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.addTab("Request", requestEditor.getComponent());
        detailTabs.addTab("Response", responseEditor.getComponent());

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll, detailTabs);
        mainSplit.setResizeWeight(0.6);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                currentlySelectedMessage = null;
                requestEditor.setMessage(new byte[0], true);
                responseEditor.setMessage(new byte[0], false);
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            synchronized (endpoints) {
                if (modelRow >= 0 && modelRow < endpoints.size()) {
                    Endpoint ep = endpoints.get(modelRow);
                    currentlySelectedMessage = ep.originalRequestResponse;
                } else {
                    currentlySelectedMessage = null;
                }
            }
            if (currentlySelectedMessage != null) {
                requestEditor.setMessage(currentlySelectedMessage.getRequest(), true);
                responseEditor.setMessage(currentlySelectedMessage.getResponse(), false);
            } else {
                requestEditor.setMessage(new byte[0], true);
                responseEditor.setMessage(new byte[0], false);
            }
        });

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
        add(mainSplit, BorderLayout.CENTER);

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

    @Override
    public IHttpService getHttpService() {
        return currentlySelectedMessage != null ? currentlySelectedMessage.getHttpService() : null;
    }

    @Override
    public byte[] getRequest() {
        return currentlySelectedMessage != null ? currentlySelectedMessage.getRequest() : null;
    }

    @Override
    public byte[] getResponse() {
        return currentlySelectedMessage != null ? currentlySelectedMessage.getResponse() : null;
    }
}
