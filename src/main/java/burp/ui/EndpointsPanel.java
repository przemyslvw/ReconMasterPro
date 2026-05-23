package burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.models.Endpoint;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class EndpointsPanel extends JPanel {

    private static final String[] COLUMNS =
        {"Risk", "Method", "Host", "Path", "Pattern", "Status"};

    private final DefaultTableModel model;
    private final List<Endpoint> endpoints = new ArrayList<>();
    private HttpRequestResponse currentlySelectedMessage;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    public EndpointsPanel(MontoyaApi api) {
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
                        if (ep.originalRequestResponse != null && ep.originalRequestResponse.request() != null) {
                            try {
                                return ep.originalRequestResponse.request().url();
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
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.addTab("Request", requestEditor.uiComponent());
        detailTabs.addTab("Response", responseEditor.uiComponent());

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll, detailTabs);
        mainSplit.setResizeWeight(0.6);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                currentlySelectedMessage = null;
                requestEditor.setRequest(null);
                responseEditor.setResponse(null);
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
                requestEditor.setRequest(currentlySelectedMessage.request());
                if (currentlySelectedMessage.response() != null) {
                    responseEditor.setResponse(currentlySelectedMessage.response());
                } else {
                    responseEditor.setResponse(null);
                }
            } else {
                requestEditor.setRequest(null);
                responseEditor.setResponse(null);
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
}
