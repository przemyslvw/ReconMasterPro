package burp;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BurpExtenderTest {

    @Test
    void extensionClassExists() {
        assertTrue(IBurpExtender.class.isAssignableFrom(BurpExtender.class),
            "BurpExtender must implement IBurpExtender");
    }
}
