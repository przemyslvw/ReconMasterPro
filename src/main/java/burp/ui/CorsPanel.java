package burp.ui;

import burp.BurpExtender;
import burp.models.CorsFinding;
import burp.modules.CorsHunter;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;

public class CorsPanel extends JPanel implements IMessageEditorController {

    private static final String[] COLUMNS =
        {"Severity", "Type", "Method", "Host", "URL"};

    private final DefaultTableModel tableModel;
    private final List<CorsFinding> findings = new ArrayList<>();
    private final JTextArea detailArea;
    private final JLabel statusLabel;
    private IHttpRequestResponse currentlySelectedMessage;
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;

    private CorsHunter hunter;

    public CorsPanel() {
        super(new BorderLayout());

        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setPreferredWidth(75);
        table.getColumnModel().getColumn(1).setPreferredWidth(220);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);
        table.getColumnModel().getColumn(3).setPreferredWidth(160);
        table.getColumnModel().getColumn(4).setPreferredWidth(420);
        table.setDefaultRenderer(Object.class, new SeverityRowRenderer());

        burp.ui.utils.ContextMenuFactory.addContextMenu(table,
            row -> {
                synchronized (findings) {
                    if (row >= 0 && row < findings.size()) {
                        return findings.get(row).originalRequestResponse;
                    }
                }
                return null;
            },
            row -> {
                synchronized (findings) {
                    if (row >= 0 && row < findings.size()) {
                        return findings.get(row).url;
                    }
                }
                return null;
            }
        );

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setText("Select a finding to view details and PoC HTML.");

        // Native Burp Message Editors
        requestEditor = BurpExtender.callbacks.createMessageEditor(this, false);
        responseEditor = BurpExtender.callbacks.createMessageEditor(this, false);

        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.addTab("Details & PoC", new JScrollPane(detailArea));
        detailTabs.addTab("Request", requestEditor.getComponent());
        detailTabs.addTab("Response", responseEditor.getComponent());

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                currentlySelectedMessage = null;
                detailArea.setText("Select a finding to view details and PoC HTML.");
                requestEditor.setMessage(new byte[0], true);
                responseEditor.setMessage(new byte[0], false);
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            CorsFinding f = findings.get(modelRow);
            showDetail(f);
            currentlySelectedMessage = f.originalRequestResponse;
            if (currentlySelectedMessage != null) {
                requestEditor.setMessage(currentlySelectedMessage.getRequest(), true);
                responseEditor.setMessage(currentlySelectedMessage.getResponse(), false);
            } else {
                requestEditor.setMessage(new byte[0], true);
                responseEditor.setMessage(new byte[0], false);
            }
        });

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusLabel = new JLabel("Findings: 0");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));

        JTextField urlField = new JTextField(30);
        urlField.putClientProperty("JTextField.placeholderText", "https://example.com/api/endpoint");
        JTextField methodField = new JTextField("GET", 5);

        JButton probeBtn = new JButton("Probe CORS");
        probeBtn.setToolTipText("Send active CORS probes to the specified URL");
        probeBtn.addActionListener(e -> {
            String url = urlField.getText().trim();
            if (url.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Enter URL to probe.");
                return;
            }
            try {
                java.net.URL parsed = new java.net.URL(url);
                String host = parsed.getHost();
                String method = methodField.getText().trim().isEmpty()
                    ? "GET" : methodField.getText().trim().toUpperCase();
                statusLabel.setText("Probing " + host + "...");
                if (hunter != null) hunter.probe(host, url, method);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Invalid URL: " + ex.getMessage());
            }
        });

        JButton copyPocBtn = new JButton("Copy PoC");
        copyPocBtn.setToolTipText("Copy PoC HTML for the selected finding to clipboard");
        copyPocBtn.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                JOptionPane.showMessageDialog(this, "Select a finding first.");
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            String poc = findings.get(modelRow).pocHtml;
            if (poc != null) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(poc), null);
                statusLabel.setText("PoC copied to clipboard.");
            }
        });

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            synchronized (findings) {
                findings.clear();
            }
            tableModel.setRowCount(0);
            detailArea.setText("Select a finding to view details and PoC HTML.");
            statusLabel.setText("Findings: 0");
            requestEditor.setMessage(new byte[0], true);
            responseEditor.setMessage(new byte[0], false);
        });

        toolbar.add(new JLabel("URL:"));
        toolbar.add(urlField);
        toolbar.add(new JLabel(" Method:"));
        toolbar.add(methodField);
        toolbar.add(probeBtn);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(copyPocBtn);
        toolbar.add(Box.createHorizontalStrut(10));
        toolbar.add(clearBtn);
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(statusLabel);

        JSplitPane split = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(table),
            detailTabs
        );
        split.setResizeWeight(0.55);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    public void setHunter(CorsHunter hunter) {
        this.hunter = hunter;
    }

    public void addFinding(CorsFinding finding) {
        SwingUtilities.invokeLater(() -> {
            int size;
            synchronized (findings) {
                boolean duplicate = findings.stream().anyMatch(f ->
                    f.type == finding.type && f.url.equals(finding.url));
                if (duplicate) return;

                findings.add(finding);
                size = findings.size();
            }
            tableModel.addRow(new Object[]{
                finding.severity,
                finding.type.name(),
                finding.method,
                finding.host,
                finding.url
            });
            statusLabel.setText("Findings: " + size);
        });
    }

    public List<CorsFinding> getFindings() {
        synchronized (findings) {
            return List.copyOf(findings);
        }
    }

    private void showDetail(CorsFinding finding) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(finding.type).append(" [").append(finding.severity).append("] ===\n\n");
        sb.append("URL    : ").append(finding.url).append("\n");
        sb.append("Method : ").append(finding.method).append("\n");
        sb.append("Probe  : ").append(finding.activeProbe ? "active" : "passive").append("\n");
        if (finding.testedOrigin != null) {
            sb.append("Origin sent: ").append(finding.testedOrigin).append("\n");
        }
        sb.append("\n--- Response headers ---\n");
        sb.append("Access-Control-Allow-Origin      : ")
          .append(finding.responseAcao != null ? finding.responseAcao : "(not present)").append("\n");
        sb.append("Access-Control-Allow-Credentials : ")
          .append(finding.responseAcac != null ? finding.responseAcac : "(not present)").append("\n");
        sb.append("\n--- PoC HTML (click 'Copy PoC') ---\n\n");
        sb.append(finding.pocHtml != null ? finding.pocHtml : "(no PoC generated)");
        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    private static class SeverityRowRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(
                table, value, selected, focus, row, column);
            if (!selected) {
                String sev = (String) table.getValueAt(row, 0);
                Color bgColor = Color.WHITE;
                if (sev != null) {
                    switch (sev) {
                        case "CRITICAL":
                            bgColor = new Color(255, 140, 140);
                            break;
                        case "HIGH":
                            bgColor = new Color(255, 195, 140);
                            break;
                        case "MEDIUM":
                            bgColor = new Color(255, 235, 160);
                            break;
                        case "LOW":
                            bgColor = new Color(205, 230, 205);
                            break;
                    }
                }
                c.setBackground(bgColor);
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
