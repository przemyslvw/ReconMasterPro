package burp.modules;

import burp.models.CloudAsset;
import burp.utils.CloudAssetDetector;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CloudAssetsAggregator extends AbstractReconHandler {

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

    public CloudAssetsAggregator(Consumer<CloudAsset> onAssetFound) {
        super("CloudAssets");
        this.onAssetFound = onAssetFound;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (isFromAuditableSource(responseReceived.toolSource())) {
            executor.submit(() -> {
                try {
                    HttpRequest request = responseReceived.initiatingRequest();
                    if (request == null) return;

                    String sourceUrl = request.url();

                    List<HttpHeader> headers = responseReceived.headers();
                    String contentType = getContentType(headers);

                    HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(request, responseReceived);

                    // ── 1. Nagłówki ─────────────────────────────────────────
                    for (HttpHeader header : headers) {
                        String name = header.name().toLowerCase().trim();
                        if (CLOUD_HEADERS.contains(name)) {
                            String sourceType = name.startsWith("content-security")
                                ? "header-csp" : "header-" + name;
                            process(CloudAssetDetector.scan(header.value(), sourceUrl, sourceType), reqResp);
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
                    logError("error: " + e.getMessage());
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
}
