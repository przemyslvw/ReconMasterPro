package burp.modules;

import burp.models.*;
import burp.utils.DatabaseManager;

import java.util.function.Consumer;

public class TimelineAnalyzer {

    private static final int HIGH_RISK_THRESHOLD = 60;

    private final DatabaseManager db;
    private final Consumer<TimelineEvent> onEvent;
    private volatile int windowMinutes = 60;

    public TimelineAnalyzer(DatabaseManager db, Consumer<TimelineEvent> onEvent) {
        this.db = db;
        this.onEvent = onEvent;
    }

    public void setWindowMinutes(int minutes) {
        this.windowMinutes = minutes;
    }

    // ── Endpoint ──────────────────────────────────────────────────────

    public void trackEndpoint(Endpoint ep) {
        int prevStatus = db.isKnownEndpoint(ep.host, ep.method, ep.path)
            ? db.getStatusCode(ep.host, ep.method, ep.path)
            : -1;

        boolean isNew = db.saveEndpoint(ep);

        if (isNew) {
            emit(new TimelineEvent("NEW_ENDPOINT", ep.host,
                String.format("New: %s %s (status %d, risk %d)",
                    ep.method, ep.path, ep.statusCode, ep.riskScore),
                riskToSeverity(ep.riskScore),
                "endpoint"));

            if (ep.riskScore >= HIGH_RISK_THRESHOLD) {
                emit(new TimelineEvent("HIGH_RISK_ENDPOINT", ep.host,
                    String.format("High-risk endpoint: %s %s (score %d)",
                        ep.method, ep.path, ep.riskScore),
                    "HIGH",
                    "endpoint"));
            }
        } else {
            // sprawdź zmianę statusu
            if (prevStatus != -1 && prevStatus != ep.statusCode) {
                emit(new TimelineEvent("ENDPOINT_CHANGED", ep.host,
                    String.format("Status changed: %s %s %d → %d",
                        ep.method, ep.path, prevStatus, ep.statusCode),
                    "MEDIUM",
                    "endpoint"));
            }
        }
    }

    // ── Technology ────────────────────────────────────────────────────

    public void trackTechnology(Technology tech) {
        boolean isNew = db.saveTechnology(tech);
        if (!isNew) return;

        String severity = tech.cves.isEmpty() ? "INFO" : tech.highestSeverity();
        String cveInfo  = tech.cves.isEmpty()
            ? ""
            : String.format(" (%d CVE, highest: %s)", tech.cves.size(), severity);

        emit(new TimelineEvent("NEW_TECH", tech.host,
            String.format("Detected: %s%s%s%s",
                tech.name,
                tech.version != null ? " " + tech.version : "",
                " [" + tech.category + "]",
                cveInfo),
            severity,
            "technology"));
    }

    // ── Secret ────────────────────────────────────────────────────────

    public void trackSecret(Secret secret) {
        db.saveSecret(secret);

        emit(new TimelineEvent("NEW_SECRET", secret.host,
            String.format("SECRET: %s — %s (entropy %.2f)",
                secret.type, secret.value, secret.entropy),
            secret.severity,
            "secret"));
    }

    // ── Helper ────────────────────────────────────────────────────────

    private void emit(TimelineEvent event) {
        db.saveEvent(event);
        onEvent.accept(event);
    }

    private String riskToSeverity(int risk) {
        if (risk >= 70) return "HIGH";
        if (risk >= 40) return "MEDIUM";
        if (risk >= 20) return "LOW";
        return "INFO";
    }
}
