package burp.models;

public enum CloudProvider {
    S3              ("AWS S3"),
    AZURE_BLOB      ("Azure Blob Storage"),
    GCS             ("Google Cloud Storage"),
    CLOUDFRONT      ("AWS CloudFront"),
    DO_SPACES       ("DigitalOcean Spaces"),
    BACKBLAZE       ("Backblaze B2"),
    UNKNOWN         ("Unknown");

    public final String displayName;

    CloudProvider(String displayName) {
        this.displayName = displayName;
    }
}
