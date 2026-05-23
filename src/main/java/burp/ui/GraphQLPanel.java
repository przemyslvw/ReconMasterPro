package burp.ui;

import burp.models.GraphQLEndpoint;
import burp.models.GraphQLField;
import burp.models.GraphQLType;
import burp.modules.GraphQLExtractor;
import burp.utils.GraphQLSchemaParser;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class GraphQLPanel extends JPanel {

    private static final String[] COLUMNS =
        {"Host", "URL", "Detected By", "Introspection", "Schema"};

    private final DefaultTableModel tableModel;
    private final List<GraphQLEndpoint> endpoints = new ArrayList<>();
    private final Map<String, GraphQLSchemaParser.ParsedSchema> schemas = new ConcurrentHashMap<>();

    private final DefaultMutableTreeNode treeRoot;
    private final DefaultTreeModel treeModel;
    private final JTree schemaTree;
    private final JLabel statusLabel;

    private GraphQLExtractor extractor;

    public GraphQLPanel() {
        super(new BorderLayout());

        // ── Tabela endpointów ────────────────────────────────────────
        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setPreferredWidth(160);  // Host
        table.getColumnModel().getColumn(1).setPreferredWidth(260);  // URL
        table.getColumnModel().getColumn(2).setPreferredWidth(110);  // Detected By
        table.getColumnModel().getColumn(3).setPreferredWidth(90);   // Introspection
        table.getColumnModel().getColumn(4).setPreferredWidth(70);   // Schema

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
                        return endpoints.get(row).url;
                    }
                }
                return null;
            }
        );

        // ── Drzewo schematu ─────────────────────────────────────────
        treeRoot = new DefaultMutableTreeNode("Select an endpoint");
        treeModel = new DefaultTreeModel(treeRoot);
        schemaTree = new JTree(treeModel);
        schemaTree.setRootVisible(true);
        schemaTree.setShowsRootHandles(true);
        schemaTree.setCellRenderer(new SchemaTreeCellRenderer());

        // kliknięcie wiersza w tabeli → pokaż schemat
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) return;
            int modelRow = table.convertRowIndexToModel(viewRow);
            showSchema(endpoints.get(modelRow));
        });

        // ── Toolbar ──────────────────────────────────────────────────
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusLabel = new JLabel("Endpoints: 0");
        JButton introspectBtn = new JButton("Run Introspection");
        introspectBtn.setToolTipText("Send __schema introspection query to selected endpoint");
        introspectBtn.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                JOptionPane.showMessageDialog(this, "Select an endpoint first.");
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            GraphQLEndpoint ep = endpoints.get(modelRow);
            statusLabel.setText("Running introspection on " + ep.host + "...");
            if (extractor != null) extractor.runIntrospection(ep);
        });

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            synchronized (endpoints) {
                endpoints.clear();
            }
            schemas.clear();
            tableModel.setRowCount(0);
            treeRoot.removeAllChildren();
            treeRoot.setUserObject("Select an endpoint");
            treeModel.reload();
            statusLabel.setText("Endpoints: 0");
        });

        toolbar.add(introspectBtn);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(clearBtn);
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(statusLabel);

        tableModel.addTableModelListener(e ->
            statusLabel.setText("Endpoints: " + tableModel.getRowCount()));

        // ── Layout ───────────────────────────────────────────────────
        JSplitPane split = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            new JScrollPane(table),
            new JScrollPane(schemaTree)
        );
        split.setResizeWeight(0.45);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    public void setExtractor(GraphQLExtractor extractor) {
        this.extractor = extractor;
    }

    public void addEndpoint(GraphQLEndpoint ep) {
        SwingUtilities.invokeLater(() -> {
            synchronized (endpoints) {
                endpoints.add(ep);
            }
            tableModel.addRow(new Object[]{
                ep.host,
                ep.url,
                ep.detectionMethod,
                ep.introspectionEnabled ? "YES" : "unknown",
                ep.schemaLoaded ? "loaded" : "-"
            });
        });
    }

    public List<GraphQLEndpoint> getEndpoints() {
        synchronized (endpoints) {
            return List.copyOf(endpoints);
        }
    }

    public void updateSchema(GraphQLEndpoint ep, GraphQLSchemaParser.ParsedSchema schema) {
        SwingUtilities.invokeLater(() -> {
            schemas.put(ep.url, schema);

            // odśwież wiersz w tabeli
            for (int i = 0; i < endpoints.size(); i++) {
                if (endpoints.get(i) == ep) {
                    tableModel.setValueAt(ep.introspectionEnabled ? "YES" : "NO", i, 3);
                    tableModel.setValueAt(ep.schemaLoaded ? "loaded" : "disabled", i, 4);
                    break;
                }
            }

            // jeśli ten endpoint jest wybrany — odśwież drzewo
            int viewRow = ((JTable) ((JScrollPane) ((JSplitPane) getComponent(1))
                .getLeftComponent()).getViewport().getView()).getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = ((JTable) ((JScrollPane) ((JSplitPane) getComponent(1))
                    .getLeftComponent()).getViewport().getView())
                    .convertRowIndexToModel(viewRow);
                if (modelRow < endpoints.size() && endpoints.get(modelRow) == ep) {
                    showSchema(ep);
                }
            }

            if (!ep.introspectionEnabled) {
                statusLabel.setText("Introspection disabled on " + ep.host);
            } else if (ep.schemaLoaded) {
                statusLabel.setText("Schema loaded — " + schema.types.size() + " types");
            }
        });
    }

    private void showSchema(GraphQLEndpoint ep) {
        treeRoot.removeAllChildren();
        treeRoot.setUserObject(ep.url);

        GraphQLSchemaParser.ParsedSchema schema = schemas.get(ep.url);
        if (schema == null || schema.types.isEmpty()) {
            treeRoot.add(new DefaultMutableTreeNode("No schema — click 'Run Introspection'"));
            treeModel.reload();
            return;
        }

        // sekcje: Queries, Mutations, Subscriptions, Types
        addTypeSection(schema, "Queries", schema.queryTypeName);
        addTypeSection(schema, "Mutations", schema.mutationTypeName);
        addTypeSection(schema, "Subscriptions", schema.subscriptionTypeName);

        DefaultMutableTreeNode typesNode = new DefaultMutableTreeNode(
            "Types (" + schema.types.size() + ")");
        for (GraphQLType type : schema.types) {
            if (isRootType(type.name, schema)) continue; // Query/Mutation/Subscription osobno
            typesNode.add(buildTypeNode(type));
        }
        treeRoot.add(typesNode);

        treeModel.reload();
        expandFirstLevel();
    }

    private void addTypeSection(GraphQLSchemaParser.ParsedSchema schema,
                                 String sectionName, String typeName) {
        if (typeName == null) return;
        GraphQLType type = schema.getType(typeName);
        if (type == null) return;

        DefaultMutableTreeNode sectionNode = new DefaultMutableTreeNode(
            sectionName + " (" + type.fields.size() + ")");
        for (GraphQLField field : type.fields) {
            sectionNode.add(new DefaultMutableTreeNode(field));
        }
        treeRoot.add(sectionNode);
    }

    private DefaultMutableTreeNode buildTypeNode(GraphQLType type) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(type);
        for (GraphQLField field : type.fields) {
            node.add(new DefaultMutableTreeNode(field));
        }
        return node;
    }

    private boolean isRootType(String name, GraphQLSchemaParser.ParsedSchema schema) {
        return name.equals(schema.queryTypeName) ||
               name.equals(schema.mutationTypeName) ||
               name.equals(schema.subscriptionTypeName);
    }

    private void expandFirstLevel() {
        for (int i = 0; i < schemaTree.getRowCount(); i++) {
            if (schemaTree.getPathForRow(i).getPathCount() <= 2) {
                schemaTree.expandRow(i);
            }
        }
    }

    // ── Renderer drzewa ───────────────────────────────────────────────
    private static class SchemaTreeCellRenderer extends DefaultTreeCellRenderer {

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value,
                boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);

            if (value instanceof DefaultMutableTreeNode) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
                Object obj = node.getUserObject();

                if (obj instanceof GraphQLField) {
                    GraphQLField field = (GraphQLField) obj;
                    setText(field.toString());
                    setFont(getFont().deriveFont(Font.PLAIN));
                } else if (obj instanceof GraphQLType) {
                    GraphQLType type = (GraphQLType) obj;
                    setText(type.toString());
                    setFont(getFont().deriveFont(Font.BOLD));
                    Color color = getForeground();
                    if (type.kind != null) {
                        switch (type.kind) {
                            case "OBJECT":
                                color = new Color(0, 100, 180);
                                break;
                            case "SCALAR":
                                color = new Color(100, 100, 100);
                                break;
                            case "ENUM":
                                color = new Color(150, 80, 0);
                                break;
                            case "INPUT_OBJECT":
                                color = new Color(0, 130, 80);
                                break;
                            case "INTERFACE":
                                color = new Color(130, 0, 130);
                                break;
                            case "UNION":
                                color = new Color(180, 50, 0);
                                break;
                        }
                    }
                    setForeground(color);
                } else if (obj instanceof String) {
                    String s = (String) obj;
                    if (s.startsWith("Queries") || s.startsWith("Mutations") ||
                            s.startsWith("Subscriptions") || s.startsWith("Types")) {
                        setFont(getFont().deriveFont(Font.BOLD));
                        setForeground(Color.BLACK);
                    }
                }
            }
            return this;
        }
    }
}
