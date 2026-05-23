package burp.utils;

import burp.IBurpExtenderCallbacks;

public class SettingsManager {

    private static final String KEY_ENTROPY      = "entropyThreshold";
    private static final String KEY_ACTIVE_SCAN  = "activeScanEnabled";
    private static final String KEY_EXPORT_FMT   = "defaultExportFormat";
    private static final String KEY_TIMELINE_WIN = "timelineWindowMinutes";

    // defaults
    private static final double  DEFAULT_ENTROPY      = 4.0;
    private static final boolean DEFAULT_ACTIVE_SCAN  = false;
    private static final String  DEFAULT_EXPORT_FMT   = "HTML";
    private static final int     DEFAULT_TIMELINE_WIN = 60;

    private final IBurpExtenderCallbacks callbacks;

    public SettingsManager(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    // ── Entropy threshold ────────────────────────────────────────────────

    public double getEntropyThreshold() {
        String v = callbacks.loadExtensionSetting(KEY_ENTROPY);
        if (v == null) return DEFAULT_ENTROPY;
        try { return Double.parseDouble(v); }
        catch (NumberFormatException e) { return DEFAULT_ENTROPY; }
    }

    public void setEntropyThreshold(double value) {
        if (value < 0.0 || value > 8.0)
            throw new IllegalArgumentException("Entropy must be in [0.0, 8.0]");
        callbacks.saveExtensionSetting(KEY_ENTROPY, String.valueOf(value));
    }

    // ── Active scan ──────────────────────────────────────────────────────

    public boolean isActiveScanEnabled() {
        String v = callbacks.loadExtensionSetting(KEY_ACTIVE_SCAN);
        return v == null ? DEFAULT_ACTIVE_SCAN : Boolean.parseBoolean(v);
    }

    public void setActiveScanEnabled(boolean enabled) {
        callbacks.saveExtensionSetting(KEY_ACTIVE_SCAN, String.valueOf(enabled));
    }

    // ── Default export format ────────────────────────────────────────────

    public String getDefaultExportFormat() {
        String v = callbacks.loadExtensionSetting(KEY_EXPORT_FMT);
        return v != null ? v : DEFAULT_EXPORT_FMT;
    }

    public void setDefaultExportFormat(String format) {
        if (!format.equals("HTML") && !format.equals("JSON")
                && !format.equals("Markdown") && !format.equals("CSV")) {
            throw new IllegalArgumentException("Unknown format: " + format);
        }
        callbacks.saveExtensionSetting(KEY_EXPORT_FMT, format);
    }

    // ── Timeline window ──────────────────────────────────────────────────

    public int getTimelineWindowMinutes() {
        String v = callbacks.loadExtensionSetting(KEY_TIMELINE_WIN);
        if (v == null) return DEFAULT_TIMELINE_WIN;
        try { return Integer.parseInt(v); }
        catch (NumberFormatException e) { return DEFAULT_TIMELINE_WIN; }
    }

    public void setTimelineWindowMinutes(int minutes) {
        if (minutes < 1 || minutes > 1440)
            throw new IllegalArgumentException("Timeline window must be in [1, 1440]");
        callbacks.saveExtensionSetting(KEY_TIMELINE_WIN, String.valueOf(minutes));
    }

    // ── Reset to defaults ────────────────────────────────────────────────

    public void resetToDefaults() {
        callbacks.saveExtensionSetting(KEY_ENTROPY,      String.valueOf(DEFAULT_ENTROPY));
        callbacks.saveExtensionSetting(KEY_ACTIVE_SCAN,  String.valueOf(DEFAULT_ACTIVE_SCAN));
        callbacks.saveExtensionSetting(KEY_EXPORT_FMT,   DEFAULT_EXPORT_FMT);
        callbacks.saveExtensionSetting(KEY_TIMELINE_WIN, String.valueOf(DEFAULT_TIMELINE_WIN));
    }
}
