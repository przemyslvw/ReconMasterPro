package burp.utils;

import burp.models.*;

import java.io.File;
import java.sql.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class DatabaseManager {

    private static final int SCHEMA_VERSION = 2;

    private final String dbPath;
    private Connection conn;

    public DatabaseManager(String dbPath) {
        this.dbPath = dbPath;
    }

    // factory method dla trybu produkcyjnego
    public static DatabaseManager forProduction() {
        String dir = System.getProperty("user.home") + File.separator + ".reconmaster";
        new File(dir).mkdirs();
        return new DatabaseManager(dir + File.separator + "reconmaster.db");
    }

    public void initialize() throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new SQLException("SQLite JDBC Driver not found in classpath. Make sure you are using the fat JAR.", e);
        }

        String url = dbPath.equals(":memory:")
            ? "jdbc:sqlite::memory:"
            : "jdbc:sqlite:" + dbPath;

        conn = DriverManager.getConnection(url);
        conn.setAutoCommit(true);

        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL");
            st.execute("PRAGMA synchronous=NORMAL");
            st.execute("PRAGMA foreign_keys=ON");
        }

        migrate();
        log("Database ready: " + dbPath);
    }

    public void close() {
        try { if (conn != null && !conn.isClosed()) conn.close(); }
        catch (SQLException e) { log("Close error: " + e.getMessage()); }
    }

    // ── Schema migration ──────────────────────────────────────────────

    private void migrate() throws SQLException {
        int version = getSchemaVersion();
        if (version < 1) {
            createSchemaV1();
            setSchemaVersion(1);
        }
        if (version < 2) {
            migrateToV2();
            setSchemaVersion(2);
        }
    }

    private void createSchemaV1() throws SQLException {
        String[] ddl = {
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",

            "CREATE TABLE IF NOT EXISTS endpoints (" +
            "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "  host TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL," +
            "  pattern_group TEXT, risk_score INTEGER NOT NULL DEFAULT 0," +
            "  status_code INTEGER, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL," +
            "  UNIQUE(host, method, path))",

            "CREATE TABLE IF NOT EXISTS technologies (" +
            "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "  host TEXT NOT NULL, name TEXT NOT NULL, version TEXT, category TEXT, severity TEXT," +
            "  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL," +
            "  UNIQUE(host, name))",

            "CREATE TABLE IF NOT EXISTS secrets (" +
            "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "  host TEXT NOT NULL, url TEXT, type TEXT NOT NULL," +
            "  severity TEXT NOT NULL, value_redacted TEXT, entropy REAL, detected_by TEXT," +
            "  first_seen INTEGER NOT NULL)",

            "CREATE TABLE IF NOT EXISTS timeline_events (" +
            "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "  event_type TEXT NOT NULL, host TEXT NOT NULL, message TEXT NOT NULL," +
            "  severity TEXT NOT NULL DEFAULT 'INFO', entity_type TEXT, entity_id INTEGER," +
            "  timestamp INTEGER NOT NULL)",

            "CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host)",
            "CREATE INDEX IF NOT EXISTS idx_timeline_ts ON timeline_events(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_timeline_host ON timeline_events(host, timestamp DESC)"
        };

        try (Statement st = conn.createStatement()) {
            for (String sql : ddl) st.execute(sql);
        }
    }

    private void migrateToV2() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute("CREATE INDEX IF NOT EXISTS idx_secrets_host ON secrets(host)");
            st.execute("CREATE INDEX IF NOT EXISTS idx_technologies_host ON technologies(host)");
        }
    }

    public int getSchemaVersion() {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT value FROM meta WHERE key = 'schema_version'");
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? Integer.parseInt(rs.getString(1)) : 0;
        } catch (Exception e) {
            return 0; // tabela meta nie istnieje jeszcze
        }
    }

    private void setSchemaVersion(int version) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)")) {
            ps.setString(1, String.valueOf(version));
            ps.executeUpdate();
        }
    }

    // ── Endpoints ─────────────────────────────────────────────────────

    /**
     * @return true jeśli endpoint był NOWY (nie istniał w DB)
     */
    public synchronized boolean saveEndpoint(Endpoint ep) {
        boolean isNew = !isKnownEndpoint(ep.host, ep.method, ep.path);
        long now = Instant.now().toEpochMilli();
        String sql = isNew
            ? "INSERT INTO endpoints(host,method,path,pattern_group,risk_score,status_code,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)"
            : "UPDATE endpoints SET last_seen=?, status_code=?, risk_score=? WHERE host=? AND method=? AND path=?";

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            if (isNew) {
                ps.setString(1, ep.host);
                ps.setString(2, ep.method);
                ps.setString(3, ep.path);
                ps.setString(4, ep.patternGroup);
                ps.setInt(5, ep.riskScore);
                ps.setInt(6, ep.statusCode);
                ps.setLong(7, now);
                ps.setLong(8, now);
            } else {
                ps.setLong(1, now);
                ps.setInt(2, ep.statusCode);
                ps.setInt(3, ep.riskScore);
                ps.setString(4, ep.host);
                ps.setString(5, ep.method);
                ps.setString(6, ep.path);
            }
            ps.executeUpdate();
        } catch (SQLException e) {
            log("saveEndpoint error: " + e.getMessage());
        }
        return isNew;
    }

    public boolean isKnownEndpoint(String host, String method, String path) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT 1 FROM endpoints WHERE host=? AND method=? AND path=? LIMIT 1")) {
            ps.setString(1, host); ps.setString(2, method); ps.setString(3, path);
            try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
        } catch (SQLException e) { return false; }
    }

    public int getStatusCode(String host, String method, String path) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT status_code FROM endpoints WHERE host=? AND method=? AND path=? LIMIT 1")) {
            ps.setString(1, host); ps.setString(2, method); ps.setString(3, path);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : -1;
            }
        } catch (SQLException e) { return -1; }
    }

    public long getFirstSeen(String host, String method, String path) {
        return queryLong("SELECT first_seen FROM endpoints WHERE host=? AND method=? AND path=?",
            host, method, path);
    }

    public long getLastSeen(String host, String method, String path) {
        return queryLong("SELECT last_seen FROM endpoints WHERE host=? AND method=? AND path=?",
            host, method, path);
    }

    // ── Technologies ──────────────────────────────────────────────────

    /**
     * @return true jeśli technologia była NOWA
     */
    public synchronized boolean saveTechnology(Technology tech) {
        boolean isNew = !isKnownTechnology(tech.host, tech.name);
        long now = Instant.now().toEpochMilli();

        try {
            if (isNew) {
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO technologies(host,name,version,category,severity,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)")) {
                    ps.setString(1, tech.host);
                    ps.setString(2, tech.name);
                    ps.setString(3, tech.version);
                    ps.setString(4, tech.category);
                    ps.setString(5, tech.highestSeverity());
                    ps.setLong(6, now);
                    ps.setLong(7, now);
                    ps.executeUpdate();
                }
            } else {
                try (PreparedStatement ps = conn.prepareStatement(
                        "UPDATE technologies SET last_seen=?, version=? WHERE host=? AND name=?")) {
                    ps.setLong(1, now);
                    ps.setString(2, tech.version);
                    ps.setString(3, tech.host);
                    ps.setString(4, tech.name);
                    ps.executeUpdate();
                }
            }
        } catch (SQLException e) {
            log("saveTechnology error: " + e.getMessage());
        }
        return isNew;
    }

    public boolean isKnownTechnology(String host, String name) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT 1 FROM technologies WHERE host=? AND name=? LIMIT 1")) {
            ps.setString(1, host); ps.setString(2, name);
            try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
        } catch (SQLException e) { return false; }
    }

    // ── Secrets ───────────────────────────────────────────────────────

    public synchronized void saveSecret(Secret secret) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO secrets(host,url,type,severity,value_redacted,entropy,detected_by,first_seen)" +
                " VALUES(?,?,?,?,?,?,?,?)")) {
            ps.setString(1, secret.host);
            ps.setString(2, secret.url);
            ps.setString(3, secret.type);
            ps.setString(4, secret.severity);
            ps.setString(5, secret.value);
            ps.setDouble(6, secret.entropy);
            ps.setString(7, secret.detectedBy);
            ps.setLong(8, Instant.now().toEpochMilli());
            ps.executeUpdate();
        } catch (SQLException e) {
            log("saveSecret error: " + e.getMessage());
        }
    }

    public int countSecrets(String host) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT COUNT(*) FROM secrets WHERE host=?")) {
            ps.setString(1, host);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) { return 0; }
    }

    // ── Timeline events ───────────────────────────────────────────────

    public synchronized void saveEvent(TimelineEvent event) {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO timeline_events(event_type,host,message,severity,entity_type,entity_id,timestamp)" +
                " VALUES(?,?,?,?,?,?,?)")) {
            ps.setString(1, event.eventType);
            ps.setString(2, event.host);
            ps.setString(3, event.message);
            ps.setString(4, event.severity);
            ps.setString(5, event.entityType);
            ps.setInt(6, event.entityId);
            ps.setLong(7, event.timestamp.toEpochMilli());
            ps.executeUpdate();
        } catch (SQLException e) {
            log("saveEvent error: " + e.getMessage());
        }
    }

    /**
     * Zwraca zdarzenia z ostatnich `minutes` minut, posortowane od najnowszego.
     */
    public List<TimelineEvent> getRecentEvents(int minutes) {
        long since = Instant.now().minusSeconds((long) minutes * 60).toEpochMilli();
        List<TimelineEvent> events = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id,event_type,host,message,severity,entity_type,entity_id,timestamp" +
                " FROM timeline_events WHERE timestamp >= ? ORDER BY timestamp DESC")) {
            ps.setLong(1, since);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    TimelineEvent ev = new TimelineEvent(
                        rs.getString("event_type"),
                        rs.getString("host"),
                        rs.getString("message"),
                        rs.getString("severity"),
                        rs.getString("entity_type")
                    );
                    ev.id        = rs.getInt("id");
                    ev.entityId  = rs.getInt("entity_id");
                    ev.timestamp = Instant.ofEpochMilli(rs.getLong("timestamp"));
                    events.add(ev);
                }
            }
        } catch (SQLException e) {
            log("getRecentEvents error: " + e.getMessage());
        }
        return events;
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private long queryLong(String sql, String... params) {
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) ps.setString(i + 1, params[i]);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getLong(1) : -1;
            }
        } catch (SQLException e) { return -1; }
    }

    private void log(String msg) {
        System.out.println("[DB] " + msg);
    }
}
