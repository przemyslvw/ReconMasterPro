package burp.models;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.time.Instant;

public class CorsFinding {

    public enum IssueType {
        REFLECTED_ORIGIN_CREDENTIALS,
        NULL_ORIGIN_CREDENTIALS,
        REFLECTED_ORIGIN,
        NULL_ORIGIN,
        CREDENTIALED_WILDCARD,
        WILDCARD_ORIGIN
    }

    public IssueType type;
    public String severity;
    public String host;
    public String url;
    public String method;
    public String testedOrigin;
    public String responseAcao;
    public String responseAcac;
    public String pocHtml;
    public Instant detectedAt;
    public boolean activeProbe;
    public transient HttpRequestResponse originalRequestResponse;

    public CorsFinding(IssueType type, String host, String url, String method) {
        this.type = type;
        this.host = host;
        this.url = url;
        this.method = method;
        this.severity = severityFor(type);
        this.detectedAt = Instant.now();
        this.activeProbe = false;
    }

    public CorsFinding(IssueType type, String host, String url, String method, HttpRequestResponse originalRequestResponse) {
        this(type, host, url, method);
        this.originalRequestResponse = originalRequestResponse;
    }

    public static String severityFor(IssueType type) {
        switch (type) {
            case REFLECTED_ORIGIN_CREDENTIALS:
            case NULL_ORIGIN_CREDENTIALS:
                return "CRITICAL";
            case REFLECTED_ORIGIN:
            case NULL_ORIGIN:
                return "HIGH";
            case CREDENTIALED_WILDCARD:
                return "MEDIUM";
            case WILDCARD_ORIGIN:
                return "LOW";
            default:
                return "UNKNOWN";
        }
    }

    @Override
    public String toString() {
        return type + " @ " + url + " [" + severity + "]";
    }
}
