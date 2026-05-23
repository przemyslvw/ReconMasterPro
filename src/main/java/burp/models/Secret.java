package burp.models;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.time.Instant;

public class Secret {
    public String type;          // "AWS Access Key", "GitHub Token", ...
    public String severity;      // CRITICAL | HIGH | MEDIUM | LOW
    public String value;         // wykryty sekret (pierwsze 40 znaków, reszta ***)
    public String fullValue;     // pełna wartość — tylko lokalnie, nigdy nie loguj
    public double entropy;       // Shannon entropy wartości
    public String context;       // ±60 znaków wokół znaleziska
    public String host;
    public String url;
    public String detectedBy;    // "regex" | "entropy"
    public Instant discoveredAt;
    public transient HttpRequestResponse originalRequestResponse;

    public Secret(String type, String severity, String fullValue,
                  String context, String host, String url, String detectedBy) {
        this.type = type;
        this.severity = severity;
        this.fullValue = fullValue;
        this.value = redact(fullValue);
        this.context = context;
        this.host = host;
        this.url = url;
        this.detectedBy = detectedBy;
        this.discoveredAt = Instant.now();
    }

    public Secret(String type, String severity, String fullValue,
                  String context, String host, String url, String detectedBy,
                  HttpRequestResponse originalRequestResponse) {
        this(type, severity, fullValue, context, host, url, detectedBy);
        this.originalRequestResponse = originalRequestResponse;
    }

    private static String redact(String v) {
        if (v == null) return "";
        if (v.length() <= 8) return "***";
        return v.substring(0, Math.min(8, v.length())) +
               "..." +
               v.substring(Math.max(0, v.length() - 4));
    }
}
