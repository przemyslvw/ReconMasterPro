package burp;

import burp.models.*;
import burp.modules.TimelineAnalyzer;
import burp.utils.DatabaseManager;
import org.junit.jupiter.api.*;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class TimelineAnalyzerTest {

    private DatabaseManager db;
    private List<TimelineEvent> emitted;
    private TimelineAnalyzer analyzer;

    @BeforeEach
    void setup() throws Exception {
        db = new DatabaseManager(":memory:");
        db.initialize();
        emitted = new ArrayList<>();
        analyzer = new TimelineAnalyzer(db, emitted::add);
    }

    @AfterEach
    void teardown() {
        db.close();
    }

    // ── Endpoint tracking ─────────────────────────────────────────────

    @Test
    void newEndpointEmitsEvent() {
        Endpoint ep = new Endpoint("example.com", "GET", "/api/users", 200);
        analyzer.trackEndpoint(ep);
        assertEquals(1, emitted.size());
        assertEquals("NEW_ENDPOINT", emitted.get(0).eventType);
    }

    @Test
    void knownEndpointDoesNotEmitEvent() {
        Endpoint ep = new Endpoint("example.com", "GET", "/api/users", 200);
        analyzer.trackEndpoint(ep); // pierwsze = nowe
        emitted.clear();
        analyzer.trackEndpoint(ep); // drugie = znane
        assertTrue(emitted.isEmpty());
    }

    @Test
    void statusChangeEmitsEndpointChangedEvent() {
        Endpoint ep1 = new Endpoint("example.com", "GET", "/admin", 200);
        analyzer.trackEndpoint(ep1);  // zapisuje status 200
        emitted.clear();

        Endpoint ep2 = new Endpoint("example.com", "GET", "/admin", 403);
        analyzer.trackEndpoint(ep2);  // status zmienił się na 403

        assertEquals(1, emitted.size());
        assertEquals("ENDPOINT_CHANGED", emitted.get(0).eventType);
        assertTrue(emitted.get(0).message.contains("200") &&
                   emitted.get(0).message.contains("403"));
    }

    @Test
    void highRiskEndpointEmitsAdditionalEvent() {
        // risk score >= 60 → osobny alert HIGH_RISK_ENDPOINT
        Endpoint ep = new Endpoint("example.com", "DELETE", "/admin/users", 200);
        ep.riskScore = 75;
        analyzer.trackEndpoint(ep);

        assertTrue(emitted.stream().anyMatch(e -> e.eventType.equals("HIGH_RISK_ENDPOINT")));
    }

    // ── Technology tracking ───────────────────────────────────────────

    @Test
    void newTechEmitsEvent() {
        Technology t = new Technology("jQuery", "JS Library", "example.com");
        t.version = "1.9.0";
        analyzer.trackTechnology(t);

        assertEquals(1, emitted.size());
        assertEquals("NEW_TECH", emitted.get(0).eventType);
    }

    @Test
    void knownTechDoesNotEmitEvent() {
        Technology t = new Technology("jQuery", "JS Library", "example.com");
        analyzer.trackTechnology(t);
        emitted.clear();
        analyzer.trackTechnology(t);
        assertTrue(emitted.isEmpty());
    }

    @Test
    void techWithCvesEmitsCriticalSeverity() {
        Technology t = new Technology("jQuery", "JS Library", "example.com");
        t.version = "1.9.0";
        CveEntry cve = new CveEntry();
        cve.cve_id = "CVE-2019-11358";
        cve.severity = "MEDIUM";
        cve.cvss = 6.1;
        cve.description = "Prototype pollution";
        cve.technology = "jQuery";
        cve.affected_before = "3.4.0";
        t.cves.add(cve);

        analyzer.trackTechnology(t);

        assertFalse(emitted.isEmpty());
        assertEquals("MEDIUM", emitted.get(0).severity);
    }

    // ── Secret tracking ───────────────────────────────────────────────

    @Test
    void secretAlwaysEmitsEvent() {
        Secret s = new Secret("AWS Key", "CRITICAL", "AKIAIOSFODNN7ABCDEF",
            "ctx", "example.com", "/app.js", "regex");
        analyzer.trackSecret(s);
        assertEquals(1, emitted.size());
        assertEquals("NEW_SECRET", emitted.get(0).eventType);
        assertEquals("CRITICAL", emitted.get(0).severity);
    }

    @Test
    void sameSecretEmitsTwice() {
        // sekrety zawsze zapisywane — każde wystąpienie jest interesujące
        Secret s1 = new Secret("AWS Key", "CRITICAL", "AKIAIOSFODNN7ABCDEF",
            "ctx1", "example.com", "/a.js", "regex");
        Secret s2 = new Secret("AWS Key", "CRITICAL", "AKIAIOSFODNN7ABCDEF",
            "ctx2", "example.com", "/b.js", "regex");
        analyzer.trackSecret(s1);
        analyzer.trackSecret(s2);
        assertEquals(2, emitted.size());
    }
}
