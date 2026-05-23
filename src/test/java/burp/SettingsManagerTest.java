package burp;

import burp.utils.SettingsManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class SettingsManagerTest {

    private Map<String, String> store;
    private IBurpExtenderCallbacks fake;
    private SettingsManager settings;

    @BeforeEach
    void setUp() {
        store = new HashMap<>();
        fake = (IBurpExtenderCallbacks) Proxy.newProxyInstance(
            IBurpExtenderCallbacks.class.getClassLoader(),
            new Class<?>[]{IBurpExtenderCallbacks.class},
            (proxy, method, args) -> {
                if ("saveExtensionSetting".equals(method.getName())) {
                    store.put((String) args[0], (String) args[1]);
                    return null;
                } else if ("loadExtensionSetting".equals(method.getName())) {
                    return store.get((String) args[0]);
                }
                Class<?> returnType = method.getReturnType();
                if (returnType == void.class) return null;
                if (returnType == boolean.class) return false;
                if (returnType == int.class) return 0;
                if (returnType == double.class) return 0.0;
                return null;
            }
        );
        settings = new SettingsManager(fake);
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
        // New instance with the same fake callbacks (which uses the same store)
        SettingsManager settings2 = new SettingsManager(fake);
        assertEquals(5.0, settings2.getEntropyThreshold(), 0.001);
    }

    @Test
    void corruptStoredValueFallsBackToDefault() {
        store.put("entropyThreshold", "not-a-number");
        assertEquals(4.0, settings.getEntropyThreshold(), 0.001);
    }
}
