package burp;

import burp.models.CveEntry;
import burp.utils.CveDatabase;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class CveDatabaseTest {

    private static CveDatabase db;

    @BeforeAll
    static void setup() {
        db = new CveDatabase();
        db.load(); // ładuje z classpath
    }

    @Test
    void findsVulnerableJQuery() {
        List<CveEntry> cves = db.query("jQuery", "1.9.0");
        assertFalse(cves.isEmpty(), "Powinien znaleźć CVE dla jQuery 1.9.0");
    }

    @Test
    void noVulnerabilitiesForPatchedJQuery() {
        List<CveEntry> cves = db.query("jQuery", "3.7.0");
        assertTrue(cves.isEmpty(), "jQuery 3.7.0 nie powinien mieć CVE");
    }

    @Test
    void unknownVersionReturnsAllCves() {
        List<CveEntry> cves = db.query("jQuery", null);
        assertFalse(cves.isEmpty());
    }

    @Test
    void unknownTechReturnsEmpty() {
        List<CveEntry> cves = db.query("UnknownLib", "1.0.0");
        assertTrue(cves.isEmpty());
    }
}
