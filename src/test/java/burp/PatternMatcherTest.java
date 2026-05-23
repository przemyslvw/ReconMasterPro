package burp;

import burp.utils.PatternMatcher;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PatternMatcherTest {

    private final PatternMatcher pm = new PatternMatcher();

    @Test
    void numericSegmentReplacedWithId() {
        assertEquals("/api/users/{id}", pm.normalize("/api/users/123"));
    }

    @Test
    void uuidSegmentReplacedWithUuid() {
        assertEquals("/api/items/{uuid}",
            pm.normalize("/api/items/550e8400-e29b-41d4-a716-446655440000"));
    }

    @Test
    void hexHashReplacedWithHash() {
        assertEquals("/assets/{hash}.js",
            pm.normalize("/assets/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4.js"));
    }

    @Test
    void staticPathUnchanged() {
        assertEquals("/login", pm.normalize("/login"));
    }

    @Test
    void multipleSegmentsNormalized() {
        assertEquals("/api/orders/{id}/items/{id}",
            pm.normalize("/api/orders/42/items/7"));
    }

    @Test
    void emptyPathReturnedAsIs() {
        assertEquals("/", pm.normalize("/"));
    }
}
