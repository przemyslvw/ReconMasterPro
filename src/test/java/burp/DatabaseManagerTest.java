package burp;

import burp.models.*;
import burp.utils.DatabaseManager;
import org.junit.jupiter.api.*;
import java.time.Instant;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class DatabaseManagerTest {

    private DatabaseManager db;

    @BeforeEach
    void setup() throws Exception {
        db = new DatabaseManager(":memory:");
        db.initialize();
    }

    @AfterEach
    void teardown() {
        db.close();
    }

    // ── Schema ────────────────────────────────────────────────────────

    @Test
    void schemaVersionIsTwoAfterInit() {
        assertEquals(2, db.getSchemaVersion());
    }

    // ── Endpoints ─────────────────────────────────────────────────────

    @Test
    void newEndpointIsUnknownBeforeSave() {
        assertFalse(db.isKnownEndpoint("example.com", "GET", "/api/users"));
    }

    @Test
    void endpointIsKnownAfterSave() {
        Endpoint ep = new Endpoint("example.com", "GET", "/api/users", 200);
        db.saveEndpoint(ep);
        assertTrue(db.isKnownEndpoint("example.com", "GET", "/api/users"));
    }

    @Test
    void saveEndpointTwiceUpdatesLastSeen() throws InterruptedException {
        Endpoint ep = new Endpoint("example.com", "GET", "/api/users", 200);
        db.saveEndpoint(ep);
        long firstSeen = db.getFirstSeen("example.com", "GET", "/api/users");

        Thread.sleep(10); // gwarantuje różne timestamps
        db.saveEndpoint(ep);

        long lastSeen = db.getLastSeen("example.com", "GET", "/api/users");
        assertTrue(lastSeen >= firstSeen);
        assertEquals(firstSeen, db.getFirstSeen("example.com", "GET", "/api/users"),
            "first_seen nie może się zmienić przy upsert");
    }

    @Test
    void saveEndpointReturnsTrueForNewFalseForKnown() {
        Endpoint ep = new Endpoint("example.com", "GET", "/api/v2", 200);
        assertTrue(db.saveEndpoint(ep),  "pierwszy zapis = nowy");
        assertFalse(db.saveEndpoint(ep), "drugi zapis = już znany");
    }

    @Test
    void getStatusCodeReturnsStoredValue() {
        Endpoint ep = new Endpoint("example.com", "GET", "/admin", 403);
        db.saveEndpoint(ep);
        assertEquals(403, db.getStatusCode("example.com", "GET", "/admin"));
    }

    // ── Technologies ──────────────────────────────────────────────────

    @Test
    void newTechIsUnknownBeforeSave() {
        assertFalse(db.isKnownTechnology("example.com", "WordPress"));
    }

    @Test
    void techIsKnownAfterSave() {
        Technology t = new Technology("WordPress", "CMS", "example.com");
        t.version = "6.2.1";
        db.saveTechnology(t);
        assertTrue(db.isKnownTechnology("example.com", "WordPress"));
    }

    @Test
    void saveTechReturnsTrueForNewFalseForKnown() {
        Technology t = new Technology("jQuery", "JS Library", "example.com");
        assertTrue(db.saveTechnology(t));
        assertFalse(db.saveTechnology(t));
    }

    // ── Secrets ───────────────────────────────────────────────────────

    @Test
    void secretIsSavedAndCountable() {
        Secret s = new Secret("AWS Access Key", "CRITICAL", "AKIAIOSFODNN7ABCDEF",
            "context", "example.com", "/app.js", "regex");
        db.saveSecret(s);
        assertEquals(1, db.countSecrets("example.com"));
    }

    @Test
    void multipleSecretsAreSaved() {
        Secret s1 = new Secret("AWS Access Key", "CRITICAL", "AKIAIOSFODNN7ABCDEF",
            "ctx", "example.com", "/a.js", "regex");
        Secret s2 = new Secret("GitHub Token", "HIGH", "ghp_16C7e42F292c6912ABCD",
            "ctx", "example.com", "/b.js", "regex");
        db.saveSecret(s1);
        db.saveSecret(s2);
        assertEquals(2, db.countSecrets("example.com"));
    }

    // ── Timeline events ───────────────────────────────────────────────

    @Test
    void savedEventAppearsInRecentQuery() {
        TimelineEvent ev = new TimelineEvent("NEW_ENDPOINT", "example.com",
            "New: GET /api/users", "INFO", "endpoint");
        db.saveEvent(ev);

        List<TimelineEvent> events = db.getRecentEvents(60); // ostatnie 60 min
        assertFalse(events.isEmpty());
        assertEquals("NEW_ENDPOINT", events.get(0).eventType);
    }

    @Test
    void oldEventNotReturnedInRecentQuery() throws Exception {
        // symulacja: zapisz event ze starym timestampem
        TimelineEvent ev = new TimelineEvent("NEW_ENDPOINT", "example.com",
            "Old event", "INFO", "endpoint");
        ev.timestamp = Instant.now().minusSeconds(7200); // 2h temu
        db.saveEvent(ev);

        List<TimelineEvent> recent = db.getRecentEvents(60); // ostatnie 60 min
        assertTrue(recent.isEmpty());
    }

    @Test
    void getRecentEventsReturnsNewestFirst() {
        for (int i = 0; i < 3; i++) {
            TimelineEvent ev = new TimelineEvent("NEW_ENDPOINT", "example.com",
                "Event " + i, "INFO", "endpoint");
            db.saveEvent(ev);
        }
        List<TimelineEvent> events = db.getRecentEvents(60);
        assertEquals(3, events.size());
        // nowszy timestamp >= starszy (indeks 0 = najnowszy)
        assertTrue(events.get(0).timestamp.toEpochMilli()
            >= events.get(events.size() - 1).timestamp.toEpochMilli());
    }
}
