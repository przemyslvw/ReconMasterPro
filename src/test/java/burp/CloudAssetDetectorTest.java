package burp;

import burp.models.CloudAsset;
import burp.models.CloudProvider;
import burp.utils.CloudAssetDetector;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class CloudAssetDetectorTest {

    // ── AWS S3 — virtual-hosted style ────────────────────────────────────

    @Test
    void detectsS3VirtualHostedUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://my-bucket.s3.amazonaws.com/path/file.js",
            "https://example.com", "body");
        assertEquals(1, found.size());
        assertEquals(CloudProvider.S3, found.get(0).provider);
        assertEquals("my-bucket", found.get(0).bucketOrAccount);
    }

    @Test
    void detectsS3RegionalVirtualHostedUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "const url = 'https://assets.s3.eu-west-1.amazonaws.com/logo.png';",
            "https://example.com", "body");
        assertTrue(found.stream().anyMatch(a -> a.provider == CloudProvider.S3));
        assertEquals("assets", found.stream()
            .filter(a -> a.provider == CloudProvider.S3)
            .findFirst().get().bucketOrAccount);
    }

    @Test
    void detectsS3PathStyleUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://s3.amazonaws.com/my-bucket/index.html",
            "https://example.com", "body");
        assertEquals(1, found.size());
        assertEquals(CloudProvider.S3, found.get(0).provider);
        assertEquals("my-bucket", found.get(0).bucketOrAccount);
    }

    @Test
    void detectsS3RegionalPathStyleUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://s3.us-east-2.amazonaws.com/backup-bucket/db.sql",
            "https://example.com", "body");
        assertEquals(1, found.size());
        assertEquals("backup-bucket", found.get(0).bucketOrAccount);
    }

    // ── Azure Blob Storage ────────────────────────────────────────────────

    @Test
    void detectsAzureBlobUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://myaccount.blob.core.windows.net/container/file.txt",
            "https://example.com", "body");
        assertEquals(1, found.size());
        assertEquals(CloudProvider.AZURE_BLOB, found.get(0).provider);
        assertEquals("myaccount", found.get(0).bucketOrAccount);
    }

    @Test
    void detectsAzureBlobRootUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "endpoint: 'https://storage123.blob.core.windows.net/'",
            "https://example.com", "body");
        assertTrue(found.stream().anyMatch(a -> a.provider == CloudProvider.AZURE_BLOB));
    }

    // ── Google Cloud Storage ──────────────────────────────────────────────

    @Test
    void detectsGcsPathStyleUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://storage.googleapis.com/my-gcs-bucket/data.json",
            "https://example.com", "body");
        assertEquals(1, found.size());
        assertEquals(CloudProvider.GCS, found.get(0).provider);
        assertEquals("my-gcs-bucket", found.get(0).bucketOrAccount);
    }

    @Test
    void detectsGcsVirtualHostedUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://my-bucket.storage.googleapis.com/",
            "https://example.com", "body");
        assertEquals(1, found.size());
        assertEquals(CloudProvider.GCS, found.get(0).provider);
        assertEquals("my-bucket", found.get(0).bucketOrAccount);
    }

    // ── AWS CloudFront ────────────────────────────────────────────────────

    @Test
    void detectsCloudfrontUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://d1234abcd.cloudfront.net/assets/app.js",
            "https://example.com", "body");
        assertEquals(1, found.size());
        assertEquals(CloudProvider.CLOUDFRONT, found.get(0).provider);
        assertEquals("d1234abcd", found.get(0).bucketOrAccount);
    }

    // ── DigitalOcean Spaces ───────────────────────────────────────────────

    @Test
    void detectsDigitalOceanSpacesUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://mybucket.nyc3.digitaloceanspaces.com/file.zip",
            "https://example.com", "body");
        assertEquals(1, found.size());
        assertEquals(CloudProvider.DO_SPACES, found.get(0).provider);
        assertEquals("mybucket", found.get(0).bucketOrAccount);
    }

    // ── Backblaze B2 ──────────────────────────────────────────────────────

    @Test
    void detectsBackblazeUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://f001.backblazeb2.com/file/my-b2-bucket/archive.tar.gz",
            "https://example.com", "body");
        assertEquals(1, found.size());
        assertEquals(CloudProvider.BACKBLAZE, found.get(0).provider);
        assertEquals("my-b2-bucket", found.get(0).bucketOrAccount);
    }

    // ── Ekstrakcja ze wielu referencji w jednym body ──────────────────────

    @Test
    void extractsMultipleAssetsFromBody() {
        String body = "const s3  = 'https://uploads.s3.amazonaws.com/';\n" +
                      "const gcs = 'https://storage.googleapis.com/backup-data/';\n";
        List<CloudAsset> found = CloudAssetDetector.scan(body, "https://example.com", "body");
        assertEquals(2, found.size());
        assertTrue(found.stream().anyMatch(a -> a.provider == CloudProvider.S3));
        assertTrue(found.stream().anyMatch(a -> a.provider == CloudProvider.GCS));
    }

    @Test
    void deduplicatesIdenticalUrlsInSameBody() {
        String body = "img1.src = 'https://assets.s3.amazonaws.com/logo.png';\n" +
                      "img2.src = 'https://assets.s3.amazonaws.com/logo.png';\n";
        List<CloudAsset> found = CloudAssetDetector.scan(body, "https://example.com", "body");
        assertEquals(1, found.size());
    }

    // ── Ekstrakcja z nagłówka CSP ────────────────────────────────────────

    @Test
    void extractsFromCspHeader() {
        String csp = "default-src 'self'; " +
                     "img-src https://media.s3.eu-central-1.amazonaws.com; " +
                     "script-src https://cdn.cloudfront.net";
        List<CloudAsset> found = CloudAssetDetector.scan(csp, "https://example.com", "header-csp");
        assertEquals(2, found.size());
        assertTrue(found.stream().anyMatch(a -> a.provider == CloudProvider.S3));
        assertTrue(found.stream().anyMatch(a -> a.provider == CloudProvider.CLOUDFRONT));
    }

    // ── Ekstrakcja z komentarzy HTML ─────────────────────────────────────

    @Test
    void extractsFromHtmlComment() {
        String html = "<!-- TODO: move to https://legacy.s3.amazonaws.com/backups/ -->";
        List<CloudAsset> found = CloudAssetDetector.scan(html, "https://example.com", "html-comment");
        assertEquals(1, found.size());
        assertEquals(CloudProvider.S3, found.get(0).provider);
        assertEquals("html-comment", found.get(0).sourceType);
    }

    // ── Brak fałszywych alarmów ──────────────────────────────────────────

    @Test
    void doesNotFlagRegularUrl() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://api.example.com/users",
            "https://example.com", "body");
        assertTrue(found.isEmpty());
    }

    @Test
    void doesNotFlagAmazonProductPages() {
        // amazon.com to nie S3
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://www.amazon.com/product/12345",
            "https://example.com", "body");
        assertTrue(found.isEmpty());
    }

    @Test
    void doesNotFlagGoogleSearchUrls() {
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://www.google.com/search?q=test",
            "https://example.com", "body");
        assertTrue(found.isEmpty());
    }

    @Test
    void doesNotFlagWindowsAzureManagementUrl() {
        // management.azure.com to nie blob storage
        List<CloudAsset> found = CloudAssetDetector.scan(
            "https://management.azure.com/subscriptions/",
            "https://example.com", "body");
        assertTrue(found.isEmpty());
    }
}
