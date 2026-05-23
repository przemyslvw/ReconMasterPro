package burp.ui;

import burp.models.CloudAsset;
import burp.models.CloudProvider;
import burp.modules.CloudAssetsAggregator;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class CloudAssetsPanel extends JPanel {

    private static final String[] COLUMNS = {
        "Provider", "Bucket / Account", "Access", "Source Type", "Source URL", "Asset URL"
    };

    private final DefaultTableModel tableModel;
    private final List<CloudAsset> assets = new ArrayList<>();
    private final JLabel statusLabel;
    private final JTextArea detailArea;

    private CloudAssetsAggregator aggregator;

    public CloudAssetsPanel() {
        super(new BorderLayout());

        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setPreferredWidth(140);  // Provider
        table.getColumnModel().getColumn(1).setPreferredWidth(150);  // Bucket/Account
        table.getColumnModel().getColumn(2).setPreferredWidth(75);   // Access
        table.getColumnModel().getColumn(3).setPreferredWidth(100);  // Source Type
        table.getColumnModel().getColumn(4).setPreferredWidth(200);  // Source URL
        table.getColumnModel().getColumn(5).setPreferredWidth(300);  // Asset URL

        table.setDefaultRenderer(Object.class, new AccessStatusRenderer());

        // panel dolny — szczegóły wybranego zasobu
        detailArea = new JTextArea(6, 60);
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) return;
            int modelRow = table.convertRowIndexToModel(viewRow);
            showDetail(assets.get(modelRow));
        });

        // ── Toolbar ──────────────────────────────────────────────────────
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusLabel = new JLabel("Assets: 0");

        JButton checkBtn = new JButton("Check Access");
        checkBtn.setToolTipText("Send HEAD request to selected asset URL via Burp");
        checkBtn.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                JOptionPane.showMessageDialog(this, "Select an asset first.");
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            CloudAsset asset = assets.get(modelRow);
            statusLabel.setText("Checking access: " + asset.bucketOrAccount + "...");
            checkAccess(asset, table, modelRow);
        });

        JTextField filterField = new JTextField(18);
        filterField.putClientProperty("JTextField.placeholderText", "Filter...");
        filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e)  { applyFilter(table, filterField.getText()); }
            public void removeUpdate(javax.swing.event.DocumentEvent e)  { applyFilter(table, filterField.getText()); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) {}
        });

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.addActionListener(e -> exportCsv());

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            assets.clear();
            tableModel.setRowCount(0);
            detailArea.setText("");
            statusLabel.setText("Assets: 0");
        });

        toolbar.add(new JLabel("Filter:"));
        toolbar.add(filterField);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(checkBtn);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(exportBtn);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(clearBtn);
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(statusLabel);

        tableModel.addTableModelListener(e ->
            statusLabel.setText("Assets: " + tableModel.getRowCount()));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(table),
            new JScrollPane(detailArea));
        split.setResizeWeight(0.70);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    public void setAggregator(CloudAssetsAggregator aggregator) {
        this.aggregator = aggregator;
    }

    public void addAsset(CloudAsset asset) {
        SwingUtilities.invokeLater(() -> {
            assets.add(asset);
            tableModel.addRow(new Object[]{
                asset.provider.displayName,
                asset.bucketOrAccount,
                asset.accessStatus,
                asset.sourceType,
                truncate(asset.sourceUrl, 80),
                asset.url
            });
        });
    }

    private void showDetail(CloudAsset a) {
        detailArea.setText(
            "Provider:    " + a.provider.displayName + "\n" +
            "Bucket/Acct: " + a.bucketOrAccount + "\n" +
            "Access:      " + a.accessStatus +
                (a.accessStatusCode > 0 ? " (HTTP " + a.accessStatusCode + ")" : "") + "\n" +
            "Source:      " + a.sourceType + "\n" +
            "Found in:    " + a.sourceUrl + "\n" +
            "Asset URL:   " + a.url + "\n" +
            "Discovered:  " + a.discoveredAt
        );
        detailArea.setCaretPosition(0);
    }

    /**
     * Wysyła żądanie HEAD przez Burp's makeHttpRequest — bez bezpośrednich połączeń.
     * Wynik: 200 → PUBLIC, 403/401 → PRIVATE, 404 → NOT_FOUND.
     */
    private void checkAccess(CloudAsset asset, JTable table, int modelRow) {
        new Thread(() -> {
            try {
                java.net.URL url = new java.net.URL(asset.url);
                String host     = url.getHost();
                int    port     = url.getPort();
                boolean useHttps = url.getProtocol().equalsIgnoreCase("https");
                if (port == -1) port = useHttps ? 443 : 80;

                burp.IHttpService service = burp.BurpExtender.helpers.buildHttpService(
                    host, port, useHttps);

                String path = url.getPath().isEmpty() ? "/" : url.getPath();
                if (url.getQuery() != null) path += "?" + url.getQuery();

                byte[] request = burp.BurpExtender.helpers.buildHttpMessage(
                    List.of(
                        "HEAD " + path + " HTTP/1.1",
                        "Host: " + host,
                        "User-Agent: Mozilla/5.0",
                        "Accept: */*",
                        "Connection: close"
                    ),
                    new byte[0]
                );

                byte[] response = burp.BurpExtender.callbacks.makeHttpRequest(service, request);
                if (response == null) {
                    updateStatus(asset, table, modelRow, "ERROR", 0);
                    return;
                }

                burp.IResponseInfo respInfo = burp.BurpExtender.helpers.analyzeResponse(response);
                int statusCode = respInfo.getStatusCode();

                String status = "ERROR";
                switch (statusCode / 100) {
                    case 2:
                        status = "PUBLIC";
                        break;
                    case 4:
                        status = (statusCode == 404) ? "NOT_FOUND" : "PRIVATE";
                        break;
                    default:
                        status = "ERROR";
                        break;
                }
                updateStatus(asset, table, modelRow, status, statusCode);

            } catch (Exception ex) {
                updateStatus(asset, table, modelRow, "ERROR", 0);
                try {
                    burp.BurpExtender.callbacks.printError(
                        "CloudAssets checkAccess: " + ex.getMessage());
                } catch (Exception ignored) {}
            }
        }, "ReconMaster-CloudCheck").start();
    }

    private void updateStatus(CloudAsset asset, JTable table, int modelRow,
                               String status, int code) {
        asset.accessStatus     = status;
        asset.accessStatusCode = code;
        SwingUtilities.invokeLater(() -> {
            tableModel.setValueAt(status, modelRow, 2);
            statusLabel.setText("Access: " + status +
                (code > 0 ? " (HTTP " + code + ")" : "") +
                " — " + asset.bucketOrAccount);
            table.repaint();
        });
    }

    private void applyFilter(JTable table, String text) {
        TableRowSorter<?> sorter = (TableRowSorter<?>) table.getRowSorter();
        sorter.setRowFilter(text.isEmpty() ? null
            : RowFilter.regexFilter("(?i)" + text, 0, 1, 3, 4, 5));
    }

    private void exportCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("cloud-assets.csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try (java.io.PrintWriter pw = new java.io.PrintWriter(fc.getSelectedFile(), "UTF-8")) {
            pw.println("provider,bucket_or_account,access,http_code,source_type,source_url,asset_url");
            for (CloudAsset a : assets) {
                pw.printf("\"%s\",\"%s\",\"%s\",%d,\"%s\",\"%s\",\"%s\"%n",
                    a.provider.displayName, a.bucketOrAccount, a.accessStatus,
                    a.accessStatusCode, a.sourceType, a.sourceUrl, a.url);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage());
        }
    }

    private String truncate(String s, int max) {
        return s != null && s.length() > max ? s.substring(0, max - 3) + "..." : s;
    }

    // ── Renderer — kolorowanie wg statusu dostępu ─────────────────────────
    private static class AccessStatusRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(
                table, value, selected, focus, row, column);
            if (!selected) {
                String status = String.valueOf(table.getValueAt(row, 2));
                switch (status) {
                    case "PUBLIC":
                        c.setBackground(new Color(255, 160, 160)); // czerwony — HIGH risk
                        break;
                    case "PRIVATE":
                        c.setBackground(new Color(210, 235, 210)); // zielony — OK
                        break;
                    case "NOT_FOUND":
                        c.setBackground(new Color(230, 230, 230)); // szary
                        break;
                    case "ERROR":
                        c.setBackground(new Color(255, 220, 180)); // pomarańczowy
                        break;
                    default:
                        c.setBackground(Color.WHITE);              // UNKNOWN
                        break;
                }
            }
            return c;
        }
    }
}
