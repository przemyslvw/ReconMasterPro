package burp.models;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class Technology {
    public String name;
    public String version;         // null jeśli nie udało się wyciągnąć
    public String category;
    public int confidence;         // 0–100 (rośnie z liczbą dopasowań)
    public String detectedBy;      // "header" | "body" | "cookie"
    public String host;
    public List<CveEntry> cves = new ArrayList<>();
    public Instant discoveredAt;
    public transient HttpRequestResponse originalRequestResponse;

    public Technology(String name, String category, String host) {
        this.name = name;
        this.category = category;
        this.host = host;
        this.discoveredAt = Instant.now();
    }

    public Technology(String name, String category, String host, HttpRequestResponse originalRequestResponse) {
        this(name, category, host);
        this.originalRequestResponse = originalRequestResponse;
    }

    public String highestSeverity() {
        int max = cves.stream()
            .mapToInt(c -> severityRank(c.severity))
            .max().orElse(-1);
        if (max == 4) return "CRITICAL";
        if (max == 3) return "HIGH";
        if (max == 2) return "MEDIUM";
        if (max == 1) return "LOW";
        return cves.isEmpty() ? "—" : "INFO";
    }

    private int severityRank(String s) {
        String upper = s.toUpperCase();
        if ("CRITICAL".equals(upper)) return 4;
        if ("HIGH".equals(upper)) return 3;
        if ("MEDIUM".equals(upper)) return 2;
        if ("LOW".equals(upper)) return 1;
        return 0;
    }
}
