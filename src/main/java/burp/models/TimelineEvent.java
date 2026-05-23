package burp.models;

import java.time.Instant;

public class TimelineEvent {
    public int id;
    public String eventType;    // NEW_ENDPOINT | ENDPOINT_CHANGED | NEW_TECH | NEW_SECRET
    public String host;
    public String message;
    public String severity;     // INFO | LOW | MEDIUM | HIGH | CRITICAL
    public String entityType;   // endpoint | technology | secret
    public int entityId;
    public Instant timestamp;

    public TimelineEvent(String eventType, String host, String message,
                         String severity, String entityType) {
        this.eventType  = eventType;
        this.host       = host;
        this.message    = message;
        this.severity   = severity;
        this.entityType = entityType;
        this.timestamp  = Instant.now();
    }
}
