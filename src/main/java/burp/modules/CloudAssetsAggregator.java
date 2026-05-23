package burp.modules;

import burp.ReconMasterPro;
import burp.models.CloudAsset;
import burp.utils.CloudAssetDetector;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ToolType;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.*;

public class CloudAssetsAggregator implements HttpHandler {

    // wyciąganie komentarzy HTML
    private static final Pattern HTML_COMMENT = Pattern.compile(
        "<!--(.*?)-?->",
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
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (responseReceived.toolSource().isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.INTRUDER, ToolType.SCANNER)) {
            executor.submit(() -> {
                try {
                    HttpRequest request = responseReceived.initiatingRequest();
                    if (request == null) return;

                    String sourceUrl = request.url();

                    List<String> rawHeaders = responseReceived.headers().stream().map(h -> h.toString()).toList();
                    String contentType = getContentType(rawHeaders);

                    HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(request, responseReceived);

                    // ── 1. Nagłówki ─────────────────────────────────────────
                    for (String header : rawHeaders) {
                        int colon = header.indexOf(':');
                        if (colon < 0) continue;
                        String name  = header.substring(0, colon).toLowerCase().trim();
                        String value = header.substring(colon + 1).trim();

                        if (CLOUD_HEADERS.contains(name)) {
                            String sourceType = name.startsWith("content-security")
                                ? "header-csp" : "header-" + name;
                            process(CloudAssetDetector.scan(value, sourceUrl, sourceType), reqResp);
                        }
                    }

                    // ── 2. Body (tylko tekstowe odpowiedzi) ──────────────────
                    if (!isTextual(contentType)) return;

                    String body = responseReceived.bodyToString();
                    if (body == null || body.isBlank()) return;

                    // 2a. Komentarze HTML — osobne źródło
                    Matcher cm = HTML_COMMENT.matcher(body);
                    while (cm.find()) {
                        process(CloudAssetDetector.scan(cm.group(1), sourceUrl, "html-comment"), reqResp);
                    }

                    // 2b. Całe body
                    process(CloudAssetDetector.scan(body, sourceUrl, "body"), reqResp);

                } catch (Exception e) {
                    if (ReconMasterPro.api != null) {
                        ReconMasterPro.api.logging().logToError("CloudAssetsAggregator: " + e.getMessage());
                    }
                }
            });
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void process(List<CloudAsset> assets, HttpRequestResponse reqResp) {
        for (CloudAsset asset : assets) {
            asset.originalRequestResponse = reqResp;
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

    private String getContentType(List<String> headers) {
        return headers.stream()
            .filter(h -> h.toLowerCase().startsWith("content-type:"))
            .findFirst()
            .orElse("")
            .toLowerCase();
    }

    public void shutdown() { executor.shutdownNow(); }
}
