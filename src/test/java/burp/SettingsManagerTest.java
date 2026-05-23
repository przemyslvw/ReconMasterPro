package burp;

import burp.utils.SettingsManager;
import burp.utils.AiProvider;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class SettingsManagerTest {

    private Map<String, String> store;
    private MontoyaApi fakeApi;
    private SettingsManager settings;

    @BeforeEach
    void setUp() {
        store = new HashMap<>();
        
        Preferences fakePreferences = (Preferences) Proxy.newProxyInstance(
            Preferences.class.getClassLoader(),
            new Class<?>[]{Preferences.class},
            (proxy, method, args) -> {
                if ("setString".equals(method.getName())) {
                    store.put((String) args[0], (String) args[1]);
                    return null;
                } else if ("getString".equals(method.getName())) {
                    return store.get((String) args[0]);
                }
                return null;
            }
        );

        Persistence fakePersistence = (Persistence) Proxy.newProxyInstance(
            Persistence.class.getClassLoader(),
            new Class<?>[]{Persistence.class},
            (proxy, method, args) -> {
                if ("preferences".equals(method.getName())) {
                    return fakePreferences;
                }
                return null;
            }
        );

        fakeApi = (MontoyaApi) Proxy.newProxyInstance(
            MontoyaApi.class.getClassLoader(),
            new Class<?>[]{MontoyaApi.class},
            (proxy, method, args) -> {
                if ("persistence".equals(method.getName())) {
                    return fakePersistence;
                }
                return null;
            }
        );

        settings = new SettingsManager(fakeApi);
    }

    // ── Entropy ──────────────────────────────────────────────────────────

    @Test
    void defaultEntropyIs4() {
        assertEquals(4.0, settings.getEntropyThreshold(), 0.001);
    }

    @Test
    void saveAndLoadEntropy() {
        settings.setEntropyThreshold(3.5);
        assertEquals(3.5, settings.getEntropyThreshold(), 0.001);
    }

    @Test
    void invalidEntropyThrowsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
            () -> settings.setEntropyThreshold(-1.0));
        assertThrows(IllegalArgumentException.class,
            () -> settings.setEntropyThreshold(9.0));
    }

    // ── Active scan ──────────────────────────────────────────────────────

    @Test
    void defaultActiveScanIsFalse() {
        assertFalse(settings.isActiveScanEnabled());
    }

    @Test
    void saveAndLoadActiveScan() {
        settings.setActiveScanEnabled(true);
        assertTrue(settings.isActiveScanEnabled());
        settings.setActiveScanEnabled(false);
        assertFalse(settings.isActiveScanEnabled());
    }

    // ── Export format ────────────────────────────────────────────────────

    @Test
    void defaultExportFormatIsHtml() {
        assertEquals("HTML", settings.getDefaultExportFormat());
    }

    @Test
    void saveAndLoadExportFormat() {
        settings.setDefaultExportFormat("JSON");
        assertEquals("JSON", settings.getDefaultExportFormat());
    }

    @Test
    void invalidExportFormatThrows() {
        assertThrows(IllegalArgumentException.class,
            () -> settings.setDefaultExportFormat("XML"));
    }

    // ── Timeline window ──────────────────────────────────────────────────

    @Test
    void defaultTimelineWindowIs60() {
        assertEquals(60, settings.getTimelineWindowMinutes());
    }

    @Test
    void saveAndLoadTimelineWindow() {
        settings.setTimelineWindowMinutes(30);
        assertEquals(30, settings.getTimelineWindowMinutes());
    }

    @Test
    void timelineWindowBoundsEnforced() {
        assertThrows(IllegalArgumentException.class,
            () -> settings.setTimelineWindowMinutes(0));
        assertThrows(IllegalArgumentException.class,
            () -> settings.setTimelineWindowMinutes(1441));
    }

    // ── Reset ────────────────────────────────────────────────────────────

    @Test
    void resetRestoresDefaults() {
        settings.setEntropyThreshold(2.0);
        settings.setActiveScanEnabled(true);
        settings.setDefaultExportFormat("CSV");
        settings.setTimelineWindowMinutes(120);

        settings.resetToDefaults();

        assertEquals(4.0, settings.getEntropyThreshold(), 0.001);
        assertFalse(settings.isActiveScanEnabled());
        assertEquals("HTML", settings.getDefaultExportFormat());
        assertEquals(60, settings.getTimelineWindowMinutes());
    }

    // ── Persistence simulation ───────────────────────────────────────────

    @Test
    void settingsPersistedInStore() {
        settings.setEntropyThreshold(5.0);
        // New instance with the same fake API (which uses the same store)
        SettingsManager settings2 = new SettingsManager(fakeApi);
        assertEquals(5.0, settings2.getEntropyThreshold(), 0.001);
    }

    @Test
    void corruptStoredValueFallsBackToDefault() {
        store.put("entropyThreshold", "not-a-number");
        assertEquals(4.0, settings.getEntropyThreshold(), 0.001);
    }

    // ── AI Integration Settings ─────────────────────────────────────────

    @Test
    void defaultAiSettingsCorrect() {
        assertEquals("", settings.getAiGoogleKey());
        assertEquals("", settings.getAiDeepSeekKey());
        assertEquals("http://localhost:11434/v1", settings.getAiLocalUrl());
        assertEquals(AiProvider.GOOGLE, settings.getAiProvider());
        assertEquals("gemini-1.5-flash", settings.getAiModel());
        assertTrue(settings.isAiMaskSecrets());
        assertTrue(settings.isAiMaskDomains());
    }

    @Test
    void saveAndLoadAiSettings() {
        settings.setAiGoogleKey("g-key-123");
        settings.setAiDeepSeekKey("ds-key-456");
        settings.setAiLocalUrl("http://127.0.0.1:8000");
        settings.setAiProvider(AiProvider.LOCAL);
        settings.setAiModel("llama3");
        settings.setAiMaskSecrets(false);
        settings.setAiMaskDomains(false);

        assertEquals("g-key-123", settings.getAiGoogleKey());
        assertEquals("ds-key-456", settings.getAiDeepSeekKey());
        assertEquals("http://127.0.0.1:8000", settings.getAiLocalUrl());
        assertEquals(AiProvider.LOCAL, settings.getAiProvider());
        assertEquals("llama3", settings.getAiModel());
        assertFalse(settings.isAiMaskSecrets());
        assertFalse(settings.isAiMaskDomains());
    }

    @Test
    void invalidAiUrlOrModelThrows() {
        assertThrows(IllegalArgumentException.class, () -> settings.setAiLocalUrl(""));
        assertThrows(IllegalArgumentException.class, () -> settings.setAiLocalUrl(null));
        assertThrows(IllegalArgumentException.class, () -> settings.setAiModel(""));
        assertThrows(IllegalArgumentException.class, () -> settings.setAiModel(null));
        assertThrows(IllegalArgumentException.class, () -> settings.setAiProvider(null));
    }

    @Test
    void resetRestoresAiDefaults() {
        settings.setAiGoogleKey("key");
        settings.setAiDeepSeekKey("key");
        settings.setAiLocalUrl("http://other:123");
        settings.setAiProvider(AiProvider.DEEPSEEK);
        settings.setAiModel("deepseek-chat");
        settings.setAiMaskSecrets(false);
        settings.setAiMaskDomains(false);

        settings.resetToDefaults();

        assertEquals("", settings.getAiGoogleKey());
        assertEquals("", settings.getAiDeepSeekKey());
        assertEquals("http://localhost:11434/v1", settings.getAiLocalUrl());
        assertEquals(AiProvider.GOOGLE, settings.getAiProvider());
        assertEquals("gemini-1.5-flash", settings.getAiModel());
        assertTrue(settings.isAiMaskSecrets());
        assertTrue(settings.isAiMaskDomains());
    }

    @Test
    void corruptAiProviderFallsBackToDefault() {
        store.put("ai.provider", "UNKNOWN_PROVIDER");
        assertEquals(AiProvider.GOOGLE, settings.getAiProvider());
    }
}
