package burp.utils;

import burp.models.CloudAsset;
import burp.models.CloudProvider;

import java.util.*;
import java.util.regex.*;

public class CloudAssetDetector {

    // ── Wzorce regex — kolejność: od najbardziej specyficznych ───────────

    // S3 virtual-hosted: bucket.s3.amazonaws.com lub bucket.s3.region.amazonaws.com
    private static final Pattern S3_VHOST = Pattern.compile(
        "https?://([a-z0-9][a-z0-9\\-]{1,61}[a-z0-9])\\.s3(?:\\.[a-z0-9\\-]+)?\\.amazonaws\\.com(?:[/\"'\\s>]|$)",
        Pattern.CASE_INSENSITIVE);

    // S3 path-style: s3.amazonaws.com/bucket lub s3.region.amazonaws.com/bucket
    private static final Pattern S3_PATH = Pattern.compile(
        "https?://s3(?:\\.[a-z0-9\\-]+)?\\.amazonaws\\.com/([a-z0-9][a-z0-9\\-\\.]{1,61}[a-z0-9])(?:[/\"'\\s>?]|$)",
        Pattern.CASE_INSENSITIVE);

    // Azure Blob: account.blob.core.windows.net
    private static final Pattern AZURE_BLOB = Pattern.compile(
        "https?://([a-z0-9]{3,24})\\.blob\\.core\\.windows\\.net(?:[/\"'\\s>]|$)",
        Pattern.CASE_INSENSITIVE);

    // GCS path-style: storage.googleapis.com/bucket
    private static final Pattern GCS_PATH = Pattern.compile(
        "https?://storage\\.googleapis\\.com/([a-z0-9][a-z0-9\\-_\\.]{1,61}[a-z0-9])(?:[/\"'\\s>?]|$)",
        Pattern.CASE_INSENSITIVE);

    // GCS virtual-hosted: bucket.storage.googleapis.com
    private static final Pattern GCS_VHOST = Pattern.compile(
        "https?://([a-z0-9][a-z0-9\\-_\\.]{1,61}[a-z0-9])\\.storage\\.googleapis\\.com(?:[/\"'\\s>]|$)",
        Pattern.CASE_INSENSITIVE);

    // CloudFront: id.cloudfront.net
    private static final Pattern CLOUDFRONT = Pattern.compile(
        "https?://([a-z0-9]+)\\.cloudfront\\.net(?:[/\"'\\s>]|$)",
        Pattern.CASE_INSENSITIVE);

    // DigitalOcean Spaces: bucket.region.digitaloceanspaces.com
    private static final Pattern DO_SPACES = Pattern.compile(
        "https?://([a-z0-9][a-z0-9\\-]{1,61})\\.([a-z0-9\\-]+)\\.digitaloceanspaces\\.com(?:[/\"'\\s>]|$)",
        Pattern.CASE_INSENSITIVE);

    // Backblaze B2: f001.backblazeb2.com/file/bucket/
    private static final Pattern BACKBLAZE = Pattern.compile(
        "https?://[a-z0-9]+\\.backblazeb2\\.com/file/([a-z0-9][a-z0-9\\-_\\.]{1,61})(?:[/\"'\\s>]|$)",
        Pattern.CASE_INSENSITIVE);

    private static class Extractor {
        private final Pattern pattern;
        private final CloudProvider provider;
        private final int bucketGroup;

        public Extractor(Pattern pattern, CloudProvider provider, int bucketGroup) {
            this.pattern = pattern;
            this.provider = provider;
            this.bucketGroup = bucketGroup;
        }

        public Pattern pattern() { return pattern; }
        public CloudProvider provider() { return provider; }
        public int bucketGroup() { return bucketGroup; }
    }

    private static final List<Extractor> EXTRACTORS = List.of(
        new Extractor(S3_VHOST,    CloudProvider.S3,          1),
        new Extractor(S3_PATH,     CloudProvider.S3,          1),
        new Extractor(AZURE_BLOB,  CloudProvider.AZURE_BLOB,  1),
        new Extractor(GCS_PATH,    CloudProvider.GCS,         1),
        new Extractor(GCS_VHOST,   CloudProvider.GCS,         1),
        new Extractor(CLOUDFRONT,  CloudProvider.CLOUDFRONT,  1),
        new Extractor(DO_SPACES,   CloudProvider.DO_SPACES,   1),
        new Extractor(BACKBLAZE,   CloudProvider.BACKBLAZE,   1)
    );

    // wzorzec wyciągający pełny URL z dopasowania (od https do końca tokenu)
    private static final Pattern URL_EXTRACTOR = Pattern.compile(
        "https?://[^\\s\"'<>]+",
        Pattern.CASE_INSENSITIVE);

    /**
     * Skanuje tekst (body, nagłówek, itp.) i zwraca listę odkrytych cloud assets.
     * Deduplikuje po deduplicationKey() w obrębie jednego wywołania.
     */
    public static List<CloudAsset> scan(String text, String sourceUrl, String sourceType) {
        if (text == null || text.isBlank()) return List.of();

        List<CloudAsset> results = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (Extractor ext : EXTRACTORS) {
            Matcher m = ext.pattern().matcher(text);
            while (m.find()) {
                String bucket = m.group(ext.bucketGroup());
                if (bucket == null || bucket.isEmpty()) continue;

                // wyciągnij pełny URL z dopasowania
                String fullUrl = extractUrl(text, m.start());

                CloudAsset asset = new CloudAsset(ext.provider(), bucket, fullUrl, sourceUrl, sourceType);
                String key = asset.deduplicationKey();
                if (seen.add(key)) {
                    results.add(asset);
                }
            }
        }

        return results;
    }

    private static String extractUrl(String text, int start) {
        // cofnij do początku tokenu URL (https://)
        int urlStart = text.lastIndexOf("https://", start);
        if (urlStart < 0) urlStart = text.lastIndexOf("http://", start);
        if (urlStart < 0 || urlStart > start) urlStart = start;

        Matcher m = URL_EXTRACTOR.matcher(text.substring(urlStart));
        if (m.find()) {
            String raw = m.group()
                .replaceAll("[\"'>]+$", "")   // usuń cudzysłowy/nawiasy na końcu
                .replaceAll(";$", "");
            return raw;
        }
        return text.substring(start, Math.min(start + 200, text.length())).split("\\s")[0];
    }
}
