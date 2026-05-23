package burp.modules;

import burp.*;
import burp.models.CloudAsset;
import burp.utils.CloudAssetDetector;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.*;

public class CloudAssetsAggregator implements IHttpListener {

    // wyciąganie komentarzy HTML
    private static final Pattern HTML_COMMENT = Pattern.compile(
        "<!--(.*?)-->",
        Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    // nagłówki, w których mogą się kryć cloud URL-e
    private static final Set<String> CLOUD_HEADERS = Set.of(
        "content-security-policy",
        "content-security-policy-report-only",
        "link",
        "location",
        "x-amz-bucket-region",
        "x-ms-blob-type"
    );

    // globalna deduplikacja: klucz = provider|url (unikalne odkrycia per wtyczka)
    private final Set<String> globalSeen = ConcurrentHashMap.newKeySet();

    private final Consumer<CloudAsset> onAssetFound;

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ReconMaster-CloudAssets");
        t.setDaemon(true);
        return t;
    });

    public CloudAssetsAggregator(Consumer<CloudAsset> onAssetFound) {
        this.onAssetFound = onAssetFound;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {
        if (messageIsRequest) return;

        executor.submit(() -> {
            try {
                byte[] response = messageInfo.getResponse();
                if (response == null) return;

                IResponseInfo respInfo = BurpExtender.helpers.analyzeResponse(response);
                String sourceUrl = BurpExtender.helpers
                    .analyzeRequest(messageInfo).getUrl().toString();

                // ── 1. Nagłówki ─────────────────────────────────────────
                for (String header : respInfo.getHeaders()) {
                    int colon = header.indexOf(':');
                    if (colon < 0) continue;
                    String name  = header.substring(0, colon).toLowerCase().trim();
                    String value = header.substring(colon + 1).trim();

                    if (CLOUD_HEADERS.contains(name)) {
                        String sourceType = name.startsWith("content-security")
                            ? "header-csp" : "header-" + name;
                        process(CloudAssetDetector.scan(value, sourceUrl, sourceType), messageInfo);
                    }
                }

                // ── 2. Body (tylko tekstowe odpowiedzi) ──────────────────
                String contentType = respInfo.getHeaders().stream()
                    .filter(h -> h.toLowerCase().startsWith("content-type:"))
                    .findFirst().orElse("").toLowerCase();

                if (!isTextual(contentType)) return;

                int bodyOffset = respInfo.getBodyOffset();
                if (bodyOffset >= response.length) return;

                String body = new String(response, bodyOffset,
                    response.length - bodyOffset, "UTF-8");

                // 2a. Komentarze HTML — osobne źródło
                Matcher cm = HTML_COMMENT.matcher(body);
                while (cm.find()) {
                    process(CloudAssetDetector.scan(cm.group(1), sourceUrl, "html-comment"), messageInfo);
                }

                // 2b. Całe body
                process(CloudAssetDetector.scan(body, sourceUrl, "body"), messageInfo);

            } catch (Exception e) {
                try {
                    BurpExtender.callbacks.printError("CloudAssetsAggregator: " + e.getMessage());
                } catch (Exception ignored) {}
            }
        });
    }

    private void process(List<CloudAsset> assets, IHttpRequestResponse messageInfo) {
        for (CloudAsset asset : assets) {
            asset.originalRequestResponse = messageInfo;
            if (globalSeen.add(asset.deduplicationKey())) {
                onAssetFound.accept(asset);
            }
        }
    }

    private boolean isTextual(String contentType) {
        return contentType.contains("text") ||
               contentType.contains("javascript") ||
               contentType.contains("json") ||
               contentType.contains("xml") ||
               contentType.isEmpty();
    }

    public void shutdown() { executor.shutdownNow(); }
}
