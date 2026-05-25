package burp;

import burp.api.montoya.BurpExtension;
import burp.modules.CloudAssetsAggregator;
import burp.modules.CorsHunter;
import burp.modules.EndpointDiscovery;
import burp.modules.GraphQLExtractor;
import burp.modules.SecretsScanner;
import burp.modules.TechStackFingerprinter;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class BurpExtenderTest {

    @Test
    void extensionClassExists() {
        assertTrue(BurpExtension.class.isAssignableFrom(ReconMasterPro.class),
            "ReconMasterPro must implement BurpExtension");
    }

    // Each long-lived HttpHandler owns an ExecutorService; the unload hook can
    // only reach modules that are fields. Locals leak threads on extension reload.
    @Test
    void holdsAllHandlerModulesAsFieldsForShutdown() {
        List<Class<?>> expected = List.of(
            EndpointDiscovery.class,
            TechStackFingerprinter.class,
            SecretsScanner.class,
            CorsHunter.class,
            GraphQLExtractor.class,
            CloudAssetsAggregator.class
        );

        for (Class<?> module : expected) {
            boolean hasField = Stream.of(ReconMasterPro.class.getDeclaredFields())
                .anyMatch(f -> f.getType().equals(module));
            assertTrue(hasField,
                "ReconMasterPro must hold " + module.getSimpleName() +
                " as a field so it can be shut down on unload");
        }
    }
}
