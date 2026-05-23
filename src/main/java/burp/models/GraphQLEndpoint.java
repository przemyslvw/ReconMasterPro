package burp.models;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.time.Instant;

public class GraphQLEndpoint {
    public String host;
    public String url;
    public String detectionMethod;  // "path", "response-body", "request-body", "content-type"
    public boolean introspectionEnabled;
    public boolean schemaLoaded;
    public Instant discoveredAt;
    public transient HttpRequestResponse originalRequestResponse;

    public GraphQLEndpoint(String host, String url, String detectionMethod) {
        this.host = host;
        this.url = url;
        this.detectionMethod = detectionMethod;
        this.introspectionEnabled = false;
        this.schemaLoaded = false;
        this.discoveredAt = Instant.now();
    }

    public GraphQLEndpoint(String host, String url, String detectionMethod, HttpRequestResponse originalRequestResponse) {
        this(host, url, detectionMethod);
        this.originalRequestResponse = originalRequestResponse;
    }
}
