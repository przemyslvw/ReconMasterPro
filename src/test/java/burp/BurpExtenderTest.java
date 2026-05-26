package burp;

import burp.api.montoya.BurpExtension;
import burp.modules.AbstractReconHandler;
import burp.modules.AiClient;
import burp.modules.CloudAssetsAggregator;
import burp.modules.CorsHunter;
import burp.modules.EndpointDiscovery;
import burp.modules.GraphQLExtractor;
import burp.modules.SecretsScanner;
import burp.modules.TechStackFingerprinter;
import burp.ui.AiAssistantPanel;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class BurpExtenderTest {

    @Test
    void extensionClassExists() {
        assertTrue(BurpExtension.class.isAssignableFrom(ReconMasterPro.class),
            "ReconMasterPro must implement BurpExtension");
    }

    // Each long-lived component owns resources (ExecutorService, threads); the
    // unload hook can only reach components that are fields — locals leak on reload.
    @Test
    void holdsAllHandlerModulesAsFieldsForShutdown() {
        List<Class<?>> expected = List.of(
            EndpointDiscovery.class,
            TechStackFingerprinter.class,
            SecretsScanner.class,
            CorsHunter.class,
            GraphQLExtractor.class,
            CloudAssetsAggregator.class,
            AiAssistantPanel.class
        );

        for (Class<?> module : expected) {
            boolean hasField = Stream.of(ReconMasterPro.class.getDeclaredFields())
                .anyMatch(f -> f.getType().equals(module));
            assertTrue(hasField,
                "ReconMasterPro must hold " + module.getSimpleName() +
                " as a field so it can be shut down on unload");
        }
    }

    // All AbstractReconHandler subclasses inherit shutdown(); AiClient owns its
    // own executor and must expose shutdown() explicitly.
    @Test
    void aiClientHasShutdownMethod() throws NoSuchMethodException {
        Method m = AiClient.class.getMethod("shutdown");
        assertNotNull(m);
    }

    @Test
    void aiAssistantPanelHasShutdownMethod() throws NoSuchMethodException {
        Method m = AiAssistantPanel.class.getMethod("shutdown");
        assertNotNull(m);
    }
}
