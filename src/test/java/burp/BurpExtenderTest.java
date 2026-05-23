package burp;

import burp.api.montoya.BurpExtension;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BurpExtenderTest {

    @Test
    void extensionClassExists() {
        assertTrue(BurpExtension.class.isAssignableFrom(ReconMasterPro.class),
            "ReconMasterPro must implement BurpExtension");
    }
}
