package burp;

import burp.models.CloudAsset;
import burp.models.CloudProvider;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CloudAssetTest {

    @Test
    void deduplicationKeyNormalizesTrailingSlash() {
        CloudAsset a = new CloudAsset(CloudProvider.S3, "my-bucket",
            "https://my-bucket.s3.amazonaws.com/", "https://example.com", "body");
        CloudAsset b = new CloudAsset(CloudProvider.S3, "my-bucket",
            "https://my-bucket.s3.amazonaws.com", "https://example.com/page", "body");
        assertEquals(a.deduplicationKey(), b.deduplicationKey());
    }

    @Test
    void deduplicationKeyStripsQueryString() {
        CloudAsset a = new CloudAsset(CloudProvider.GCS, "bucket",
            "https://storage.googleapis.com/bucket/file.js?v=123", "https://x.com", "body");
        CloudAsset b = new CloudAsset(CloudProvider.GCS, "bucket",
            "https://storage.googleapis.com/bucket/file.js", "https://x.com", "body");
        assertEquals(a.deduplicationKey(), b.deduplicationKey());
    }

    @Test
    void defaultAccessStatusIsUnknown() {
        CloudAsset asset = new CloudAsset(CloudProvider.AZURE_BLOB, "myaccount",
            "https://myaccount.blob.core.windows.net/", "https://x.com", "header-csp");
        assertEquals("UNKNOWN", asset.accessStatus);
        assertEquals(0, asset.accessStatusCode);
    }

    @Test
    void differentProvidersHaveDifferentDeduplicationKeys() {
        CloudAsset s3  = new CloudAsset(CloudProvider.S3, "bucket",
            "https://bucket.s3.amazonaws.com", "https://x.com", "body");
        CloudAsset gcs = new CloudAsset(CloudProvider.GCS, "bucket",
            "https://bucket.s3.amazonaws.com", "https://x.com", "body");
        assertNotEquals(s3.deduplicationKey(), gcs.deduplicationKey());
    }
}
