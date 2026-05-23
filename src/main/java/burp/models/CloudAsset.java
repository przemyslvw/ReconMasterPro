package burp.models;

import java.time.Instant;

public class CloudAsset {
    public CloudProvider provider;
    public String bucketOrAccount;   // nazwa bucketu / konta storage
    public String url;               // pełny URL odkryty w ruchu
    public String sourceUrl;         // URL strony/zasobu, w którym znaleziono referencję
    public String sourceType;        // "body", "header-csp", "header-link", "html-comment"
    public String accessStatus;      // "UNKNOWN" | "PUBLIC" | "PRIVATE" | "NOT_FOUND" | "ERROR"
    public int    accessStatusCode;  // HTTP kod odpowiedzi z weryfikacji (0 = nie sprawdzano)
    public Instant discoveredAt;

    public CloudAsset(CloudProvider provider, String bucketOrAccount,
                      String url, String sourceUrl, String sourceType) {
        this.provider         = provider;
        this.bucketOrAccount  = bucketOrAccount;
        this.url              = url;
        this.sourceUrl        = sourceUrl;
        this.sourceType       = sourceType;
        this.accessStatus     = "UNKNOWN";
        this.accessStatusCode = 0;
        this.discoveredAt     = Instant.now();
    }

    /** Zwraca klucz deduplikacji — provider + znormalizowany URL bucketu. */
    public String deduplicationKey() {
        // strip trailing slash + query
        String base = url.split("[?#]")[0].replaceAll("/+$", "");
        return provider.name() + "|" + base;
    }
}
