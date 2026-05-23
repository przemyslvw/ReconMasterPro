package burp.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

public class SettingsManager {

    private static final String KEY_ENTROPY      = "entropyThreshold";
    private static final String KEY_ACTIVE_SCAN  = "activeScanEnabled";
    private static final String KEY_EXPORT_FMT   = "defaultExportFormat";
    private static final String KEY_TIMELINE_WIN = "timelineWindowMinutes";

    private static final String KEY_AI_GOOGLE_KEY   = "ai.google.key";
    private static final String KEY_AI_DEEPSEEK_KEY  = "ai.deepseek.key";
    private static final String KEY_AI_LOCAL_URL     = "ai.local.url";
    private static final String KEY_AI_PROVIDER      = "ai.provider";
    private static final String KEY_AI_MODEL         = "ai.model";
    private static final String KEY_AI_MASK_SECRETS  = "ai.opsec.mask_secrets";
    private static final String KEY_AI_MASK_DOMAINS  = "ai.opsec.mask_domains";

    // defaults
    private static final double  DEFAULT_ENTROPY      = 4.0;
    private static final boolean DEFAULT_ACTIVE_SCAN  = false;
    private static final String  DEFAULT_EXPORT_FMT   = "HTML";
    private static final int     DEFAULT_TIMELINE_WIN = 60;

    private static final String  DEFAULT_AI_GOOGLE_KEY   = "";
    private static final String  DEFAULT_AI_DEEPSEEK_KEY  = "";
    private static final String  DEFAULT_AI_LOCAL_URL     = "http://localhost:11434/v1";
    private static final String  DEFAULT_AI_PROVIDER      = AiProvider.GOOGLE.name();
    private static final String  DEFAULT_AI_MODEL         = "gemini-1.5-flash";
    private static final boolean DEFAULT_AI_MASK_SECRETS  = true;
    private static final boolean DEFAULT_AI_MASK_DOMAINS  = true;

    private final Preferences preferences;

    public SettingsManager(MontoyaApi api) {
        this.preferences = api.persistence().preferences();
    }

    // ── Entropy threshold ────────────────────────────────────────────────

    public double getEntropyThreshold() {
        String v = preferences.getString(KEY_ENTROPY);
        if (v == null) return DEFAULT_ENTROPY;
        try { return Double.parseDouble(v); }
        catch (NumberFormatException e) { return DEFAULT_ENTROPY; }
    }

    public void setEntropyThreshold(double value) {
        if (value < 0.0 || value > 8.0)
            throw new IllegalArgumentException("Entropy must be in [0.0, 8.0]");
        preferences.setString(KEY_ENTROPY, String.valueOf(value));
    }

    // ── Active scan ──────────────────────────────────────────────────────

    public boolean isActiveScanEnabled() {
        String v = preferences.getString(KEY_ACTIVE_SCAN);
        return v == null ? DEFAULT_ACTIVE_SCAN : Boolean.parseBoolean(v);
    }

    public void setActiveScanEnabled(boolean enabled) {
        preferences.setString(KEY_ACTIVE_SCAN, String.valueOf(enabled));
    }

    // ── Default export format ────────────────────────────────────────────

    public String getDefaultExportFormat() {
        String v = preferences.getString(KEY_EXPORT_FMT);
        return v != null ? v : DEFAULT_EXPORT_FMT;
    }

    public void setDefaultExportFormat(String format) {
        if (!format.equals("HTML") && !format.equals("JSON")
                && !format.equals("Markdown") && !format.equals("CSV")) {
            throw new IllegalArgumentException("Unknown format: " + format);
        }
        preferences.setString(KEY_EXPORT_FMT, format);
    }

    // ── Timeline window ──────────────────────────────────────────────────

    public int getTimelineWindowMinutes() {
        String v = preferences.getString(KEY_TIMELINE_WIN);
        if (v == null) return DEFAULT_TIMELINE_WIN;
        try { return Integer.parseInt(v); }
        catch (NumberFormatException e) { return DEFAULT_TIMELINE_WIN; }
    }

    public void setTimelineWindowMinutes(int minutes) {
        if (minutes < 1 || minutes > 1440)
            throw new IllegalArgumentException("Timeline window must be in [1, 1440]");
        preferences.setString(KEY_TIMELINE_WIN, String.valueOf(minutes));
    }

    // ── AI Google Key ────────────────────────────────────────────────────

    public String getAiGoogleKey() {
        String v = preferences.getString(KEY_AI_GOOGLE_KEY);
        return v != null ? v : DEFAULT_AI_GOOGLE_KEY;
    }

    public void setAiGoogleKey(String key) {
        if (key == null) key = "";
        preferences.setString(KEY_AI_GOOGLE_KEY, key);
    }

    // ── AI DeepSeek Key ──────────────────────────────────────────────────

    public String getAiDeepSeekKey() {
        String v = preferences.getString(KEY_AI_DEEPSEEK_KEY);
        return v != null ? v : DEFAULT_AI_DEEPSEEK_KEY;
    }

    public void setAiDeepSeekKey(String key) {
        if (key == null) key = "";
        preferences.setString(KEY_AI_DEEPSEEK_KEY, key);
    }

    // ── AI Local URL ─────────────────────────────────────────────────────

    public String getAiLocalUrl() {
        String v = preferences.getString(KEY_AI_LOCAL_URL);
        return v != null ? v : DEFAULT_AI_LOCAL_URL;
    }

    public void setAiLocalUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("Local API URL cannot be empty");
        }
        preferences.setString(KEY_AI_LOCAL_URL, url.trim());
    }

    // ── AI Provider ──────────────────────────────────────────────────────

    public AiProvider getAiProvider() {
        String v = preferences.getString(KEY_AI_PROVIDER);
        if (v == null) return AiProvider.valueOf(DEFAULT_AI_PROVIDER);
        try {
            return AiProvider.valueOf(v);
        } catch (IllegalArgumentException e) {
            return AiProvider.valueOf(DEFAULT_AI_PROVIDER);
        }
    }

    public void setAiProvider(AiProvider provider) {
        if (provider == null) {
            throw new IllegalArgumentException("AI Provider cannot be null");
        }
        preferences.setString(KEY_AI_PROVIDER, provider.name());
    }

    // ── AI Model ─────────────────────────────────────────────────────────

    public String getAiModel() {
        String v = preferences.getString(KEY_AI_MODEL);
        return v != null ? v : DEFAULT_AI_MODEL;
    }

    public void setAiModel(String model) {
        if (model == null || model.trim().isEmpty()) {
            throw new IllegalArgumentException("Model name cannot be empty");
        }
        preferences.setString(KEY_AI_MODEL, model.trim());
    }

    // ── AI OpSec Mask Secrets ───────────────────────────────────────────

    public boolean isAiMaskSecrets() {
        String v = preferences.getString(KEY_AI_MASK_SECRETS);
        return v == null ? DEFAULT_AI_MASK_SECRETS : Boolean.parseBoolean(v);
    }

    public void setAiMaskSecrets(boolean mask) {
        preferences.setString(KEY_AI_MASK_SECRETS, String.valueOf(mask));
    }

    // ── AI OpSec Mask Domains ───────────────────────────────────────────

    public boolean isAiMaskDomains() {
        String v = preferences.getString(KEY_AI_MASK_DOMAINS);
        return v == null ? DEFAULT_AI_MASK_DOMAINS : Boolean.parseBoolean(v);
    }

    public void setAiMaskDomains(boolean mask) {
        preferences.setString(KEY_AI_MASK_DOMAINS, String.valueOf(mask));
    }

    // ── Reset to defaults ────────────────────────────────────────────────

    public void resetToDefaults() {
        preferences.setString(KEY_ENTROPY,      String.valueOf(DEFAULT_ENTROPY));
        preferences.setString(KEY_ACTIVE_SCAN,  String.valueOf(DEFAULT_ACTIVE_SCAN));
        preferences.setString(KEY_EXPORT_FMT,   DEFAULT_EXPORT_FMT);
        preferences.setString(KEY_TIMELINE_WIN, String.valueOf(DEFAULT_TIMELINE_WIN));
        preferences.setString(KEY_AI_GOOGLE_KEY,  DEFAULT_AI_GOOGLE_KEY);
        preferences.setString(KEY_AI_DEEPSEEK_KEY, DEFAULT_AI_DEEPSEEK_KEY);
        preferences.setString(KEY_AI_LOCAL_URL,   DEFAULT_AI_LOCAL_URL);
        preferences.setString(KEY_AI_PROVIDER,    DEFAULT_AI_PROVIDER);
        preferences.setString(KEY_AI_MODEL,       DEFAULT_AI_MODEL);
        preferences.setString(KEY_AI_MASK_SECRETS, String.valueOf(DEFAULT_AI_MASK_SECRETS));
        preferences.setString(KEY_AI_MASK_DOMAINS, String.valueOf(DEFAULT_AI_MASK_DOMAINS));
    }
}
