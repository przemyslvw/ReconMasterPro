package burp.models;

import java.time.Instant;

public class Endpoint {
    public String host;
    public String method;
    public String path;
    public String patternGroup;
    public int statusCode;
    public int riskScore;
    public Instant discoveredAt;

    public Endpoint(String host, String method, String path, int statusCode) {
        this.host = host;
        this.method = method;
        this.path = path;
        this.statusCode = statusCode;
        this.discoveredAt = Instant.now();
    }
}
