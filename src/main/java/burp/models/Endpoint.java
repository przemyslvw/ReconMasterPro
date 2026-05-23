package burp.models;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.time.Instant;

public class Endpoint {
    public String host;
    public String method;
    public String path;
    public String patternGroup;
    public int statusCode;
    public int riskScore;
    public Instant discoveredAt;
    public transient HttpRequestResponse originalRequestResponse;

    public Endpoint(String host, String method, String path, int statusCode) {
        this.host = host;
        this.method = method;
        this.path = path;
        this.statusCode = statusCode;
        this.discoveredAt = Instant.now();
    }

    public Endpoint(String host, String method, String path, int statusCode, HttpRequestResponse originalRequestResponse) {
        this(host, method, path, statusCode);
        this.originalRequestResponse = originalRequestResponse;
    }
}
