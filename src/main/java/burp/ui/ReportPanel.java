package burp.ui;

import burp.modules.ReportGenerator;
import burp.models.ReportData;

import javax.swing.*;
import java.awt.*;
import java.io.File;

public class ReportPanel extends JPanel {

    private final ReportGenerator generator;

    private final JComboBox<String> formatCombo;
    private final JTextField targetField;
    private final JLabel statusLabel;
    private final JTextArea summaryArea;

    public ReportPanel(ReportGenerator generator) {
        super(new BorderLayout());
        this.generator = generator;

        // ── Toolbar ──────────────────────────────────────────────────────
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));

        targetField = new JTextField("", 20);
        targetField.putClientProperty("JTextField.placeholderText", "target host (optional)");

        formatCombo = new JComboBox<>(new String[]{"HTML", "JSON", "Markdown", "CSV (ZIP)"});

        JButton exportBtn = new JButton("Export Report");
        exportBtn.addActionListener(e -> onExport());

        JButton refreshBtn = new JButton("Refresh Summary");
        refreshBtn.addActionListener(e -> refreshSummary());

        toolbar.add(new JLabel("Target:"));
        toolbar.add(targetField);
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(new JLabel("Format:"));
        toolbar.add(formatCombo);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(exportBtn);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(refreshBtn);

        // ── Podgląd summary ───────────────────────────────────────────────
        summaryArea = new JTextArea();
        summaryArea.setEditable(false);
        summaryArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        summaryArea.setMargin(new Insets(12, 12, 12, 12));
        summaryArea.setText("Click 'Refresh Summary' to see current data counts.");

        statusLabel = new JLabel("Ready.");
        JPanel statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusBar.add(statusLabel);

        add(toolbar,            BorderLayout.NORTH);
        add(new JScrollPane(summaryArea), BorderLayout.CENTER);
        add(statusBar,          BorderLayout.SOUTH);
    }

    private void onExport() {
        String format = (String) formatCombo.getSelectedItem();
        String ext    = switch (format) {
            case "JSON"      -> ".json";
            case "Markdown"  -> ".md";
            case "CSV (ZIP)" -> ".zip";
            default          -> ".html";
        };

        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("reconmaster-report" + ext));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File outFile = fc.getSelectedFile();
        String host  = targetField.getText().trim();
        if (host.isEmpty()) host = "unknown";

        ReportGenerator.Format fmt = switch (format) {
            case "JSON"      -> ReportGenerator.Format.JSON;
            case "Markdown"  -> ReportGenerator.Format.MARKDOWN;
            case "CSV (ZIP)" -> ReportGenerator.Format.CSV;
            default          -> ReportGenerator.Format.HTML;
        };

        final String targetHost = host;
        final ReportGenerator.Format finalFmt = fmt;
        statusLabel.setText("Generating report...");

        new Thread(() -> {
            try {
                generator.export(finalFmt, targetHost, outFile);
                SwingUtilities.invokeLater(() ->
                    statusLabel.setText("Saved: " + outFile.getAbsolutePath()));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Error: " + ex.getMessage());
                    JOptionPane.showMessageDialog(ReportPanel.this,
                        "Export failed:\n" + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
                });
            }
        }, "ReconMaster-Report").start();
    }

    private void refreshSummary() {
        String host = targetField.getText().trim();
        if (host.isEmpty()) host = "unknown";

        ReportData snap = generator.snapshot(host);
        summaryArea.setText(
            "=== ReconMaster Pro — Data Summary ===\n\n" +
            "Target Host:      " + snap.targetHost + "\n" +
            "Snapshot:         " + snap.generatedAt + "\n\n" +
            "Endpoints:        " + snap.endpoints.size()        + "\n" +
            "Technologies:     " + snap.technologies.size()     + "\n" +
            "Secrets:          " + snap.secrets.size()          +
                (snap.criticalCount() > 0
                    ? "  ← " + snap.criticalCount() + " CRITICAL!" : "") + "\n" +
            "CORS Findings:    " + snap.corsFindings.size()     + "\n" +
            "Cloud Assets:     " + snap.cloudAssets.size()      + "\n" +
            "GraphQL Endpoints:" + snap.graphqlEndpoints.size() + "\n\n" +
            "Export formats available: HTML, JSON, Markdown, CSV (ZIP)\n"
        );
        statusLabel.setText("Summary refreshed.");
    }
}
