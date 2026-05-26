package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.UserInterface;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Smoke-tests that ReconMasterPro.initialize() completes without crashing.
 * Uses JDK dynamic proxies to stub MontoyaApi — no external mock library needed.
 */
class ReconMasterProIntegrationTest {

    @Test
    void initializeDoesNotThrowAndRegistersUnloadHandler() throws Exception {
        AtomicReference<ExtensionUnloadingHandler> capturedUnloadHandler = new AtomicReference<>();
        Map<String, String> prefs = new HashMap<>();

        Preferences fakePrefs = proxy(Preferences.class, (method, args) -> {
            if ("setString".equals(method.getName())) { prefs.put((String) args[0], (String) args[1]); return null; }
            if ("getString".equals(method.getName())) { return prefs.get(args[0]); }
            return null;
        });

        Persistence fakePersistence = proxy(Persistence.class, (method, args) ->
            "preferences".equals(method.getName()) ? fakePrefs : null);

        Extension fakeExtension = proxy(Extension.class, (method, args) -> {
            if ("registerUnloadingHandler".equals(method.getName())) {
                capturedUnloadHandler.set((ExtensionUnloadingHandler) args[0]);
            }
            return null;
        });

        Logging fakeLogging = proxy(Logging.class, (method, args) -> null);

        Http fakeHttp = proxy(Http.class, (method, args) -> null);

        UserInterface fakeUi = proxy(UserInterface.class, (method, args) -> null);

        MontoyaApi fakeApi = proxy(MontoyaApi.class, (method, args) -> switch (method.getName()) {
            case "persistence"  -> fakePersistence;
            case "extension"    -> fakeExtension;
            case "logging"      -> fakeLogging;
            case "http"         -> fakeHttp;
            case "userInterface" -> fakeUi;
            default             -> null;
        });

        ReconMasterPro ext = new ReconMasterPro();

        // initialize() itself must not throw
        assertDoesNotThrow(() -> ext.initialize(fakeApi));

        // Flush the EDT so SwingUtilities.invokeLater tasks complete
        SwingUtilities.invokeAndWait(() -> {});

        // The unloading handler must have been registered
        assertNotNull(capturedUnloadHandler.get(),
            "initialize() must call api.extension().registerUnloadingHandler(...)");

        // Unloading handler must execute without exceptions
        assertDoesNotThrow(() -> capturedUnloadHandler.get().extensionUnloaded(),
            "unloadingHandler must not throw");
    }

    // ── helper ──────────────────────────────────────────────────────────

    @FunctionalInterface
    interface MethodHandler {
        Object handle(java.lang.reflect.Method method, Object[] args) throws Throwable;
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> iface, MethodHandler handler) {
        return (T) Proxy.newProxyInstance(
            iface.getClassLoader(),
            new Class<?>[]{ iface },
            (proxy, method, args) -> {
                try {
                    return handler.handle(method, args);
                } catch (Exception e) {
                    return null;
                }
            }
        );
    }
}
