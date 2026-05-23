package burp.ui;

import burp.utils.SettingsManager;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

public class SettingsPanel extends JPanel {

    private final SettingsManager settings;

    private final JSpinner entropySpinner;
    private final JCheckBox activeScanCheck;
    private final JComboBox<String> exportFormatCombo;
    private final JSpinner timelineWindowSpinner;
    private final JLabel statusLabel;
    private final Runnable onSaveCallback;

    public SettingsPanel(SettingsManager settings) {
        this(settings, null);
    }

    public SettingsPanel(SettingsManager settings, Runnable onSaveCallback) {
        super(new BorderLayout());
        this.settings = settings;
        this.onSaveCallback = onSaveCallback;

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        GridBagConstraints lc = labelConstraints();
        GridBagConstraints fc = fieldConstraints();

        // ── Secrets Scanner ──────────────────────────────────────────────
        JPanel secretsGroup = new JPanel(new GridBagLayout());
        secretsGroup.setBorder(new TitledBorder("Secrets Scanner"));

        entropySpinner = new JSpinner(
            new SpinnerNumberModel(settings.getEntropyThreshold(), 0.0, 8.0, 0.1));
        ((JSpinner.DefaultEditor) entropySpinner.getEditor())
            .getTextField().setColumns(6);

        secretsGroup.add(label("Entropy threshold:"), lc);
        secretsGroup.add(entropySpinner,              fc);
        secretsGroup.add(new JLabel(
            "<html><small style='color:#888'>Default: 4.0 &nbsp;|&nbsp;" +
            "Higher = less noise, Lower = more findings</small></html>"),
            wideConstraints());

        // ── Scanning ─────────────────────────────────────────────────────
        JPanel scanGroup = new JPanel(new GridBagLayout());
        scanGroup.setBorder(new TitledBorder("Scanning"));

        activeScanCheck = new JCheckBox(
            "Enable active endpoint probing", settings.isActiveScanEnabled());
        scanGroup.add(activeScanCheck, wideConstraints());
        scanGroup.add(new JLabel(
            "<html><small style='color:#888'>Warning: sends additional HTTP requests" +
            " to the target</small></html>"),
            wideConstraints());

        // ── Timeline ─────────────────────────────────────────────────────
        JPanel timelineGroup = new JPanel(new GridBagLayout());
        timelineGroup.setBorder(new TitledBorder("Timeline"));

        timelineWindowSpinner = new JSpinner(
            new SpinnerNumberModel(settings.getTimelineWindowMinutes(), 1, 1440, 5));
        ((JSpinner.DefaultEditor) timelineWindowSpinner.getEditor())
            .getTextField().setColumns(6);

        timelineGroup.add(label("Window (minutes):"), lc);
        timelineGroup.add(timelineWindowSpinner,      fc);

        // ── Report ───────────────────────────────────────────────────────
        JPanel reportGroup = new JPanel(new GridBagLayout());
        reportGroup.setBorder(new TitledBorder("Report"));

        exportFormatCombo = new JComboBox<>(
            new String[]{"HTML", "JSON", "Markdown", "CSV"});
        exportFormatCombo.setSelectedItem(settings.getDefaultExportFormat());

        reportGroup.add(label("Default export format:"), lc);
        reportGroup.add(exportFormatCombo,               fc);

        // ── Buttons ──────────────────────────────────────────────────────
        JButton saveBtn  = new JButton("Save");
        JButton resetBtn = new JButton("Reset to Defaults");

        saveBtn.addActionListener(e  -> onSave());
        resetBtn.addActionListener(e -> onReset());

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(resetBtn);
        buttonPanel.add(saveBtn);

        statusLabel = new JLabel(" ");

        // ── Layout ───────────────────────────────────────────────────────
        JPanel groups = new JPanel();
        groups.setLayout(new BoxLayout(groups, BoxLayout.Y_AXIS));
        groups.add(secretsGroup);
        groups.add(Box.createVerticalStrut(8));
        groups.add(scanGroup);
        groups.add(Box.createVerticalStrut(8));
        groups.add(timelineGroup);
        groups.add(Box.createVerticalStrut(8));
        groups.add(reportGroup);

        JPanel center = new JPanel(new BorderLayout());
        center.add(groups, BorderLayout.NORTH);

        JPanel south = new JPanel(new BorderLayout());
        south.add(statusLabel, BorderLayout.WEST);
        south.add(buttonPanel, BorderLayout.EAST);

        add(center, BorderLayout.CENTER);
        add(south,  BorderLayout.SOUTH);
    }

    // ── Actions ──────────────────────────────────────────────────────────

    private void onSave() {
        try {
            settings.setEntropyThreshold(
                ((Number) entropySpinner.getValue()).doubleValue());
            settings.setActiveScanEnabled(activeScanCheck.isSelected());
            settings.setTimelineWindowMinutes(
                ((Number) timelineWindowSpinner.getValue()).intValue());
            settings.setDefaultExportFormat(
                (String) exportFormatCombo.getSelectedItem());

            if (onSaveCallback != null) {
                onSaveCallback.run();
            }
            statusLabel.setText("Settings saved.");
        } catch (IllegalArgumentException ex) {
            statusLabel.setText("Error: " + ex.getMessage());
            JOptionPane.showMessageDialog(this,
                "Invalid value:\n" + ex.getMessage(), "Validation Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onReset() {
        int confirm = JOptionPane.showConfirmDialog(this,
            "Reset all settings to defaults?", "Confirm Reset",
            JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        settings.resetToDefaults();

        entropySpinner.setValue(settings.getEntropyThreshold());
        activeScanCheck.setSelected(settings.isActiveScanEnabled());
        timelineWindowSpinner.setValue(settings.getTimelineWindowMinutes());
        exportFormatCombo.setSelectedItem(settings.getDefaultExportFormat());

        if (onSaveCallback != null) {
            onSaveCallback.run();
        }
        statusLabel.setText("Settings reset to defaults.");
    }

    // ── GridBagConstraints helpers ────────────────────────────────────────

    private GridBagConstraints labelConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(4, 0, 4, 8);
        c.gridx = 0; c.gridy = GridBagConstraints.RELATIVE;
        return c;
    }

    private GridBagConstraints fieldConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(4, 0, 4, 0);
        c.gridx = 1; c.gridy = GridBagConstraints.RELATIVE;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        return c;
    }

    private GridBagConstraints wideConstraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.anchor    = GridBagConstraints.WEST;
        c.insets    = new Insets(2, 0, 6, 0);
        c.gridx     = 0; c.gridy = GridBagConstraints.RELATIVE;
        c.gridwidth = 2;
        c.fill      = GridBagConstraints.HORIZONTAL;
        c.weightx   = 1.0;
        return c;
    }

    private JLabel label(String text) {
        return new JLabel(text);
    }
}
