package burp.modules;

import burp.ReconMasterPro;
import burp.models.Endpoint;
import burp.utils.PatternMatcher;
import burp.utils.RiskScorer;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ToolType;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.*;

public class EndpointDiscovery implements HttpHandler {

    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private final PatternMatcher patternMatcher = new PatternMatcher();
    private final RiskScorer riskScorer = new RiskScorer();

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ReconMaster-Discovery");
        t.setDaemon(true);
        return t;
    });

    private final Consumer<Endpoint> onEndpointFound;

    private static final Pattern URL_RE = Pattern.compile(
        "(?:href|src|action|url|endpoint|path)[\"'\\s]*[:=][\"'\\s]*([\"'/][^\"'\\s<>{}]+)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern FULL_URL_RE = Pattern.compile(
        "https?://[^\"'\\s<>]+"
    );

    public EndpointDiscovery(Consumer<Endpoint> onEndpointFound) {
        this.onEndpointFound = onEndpointFound;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (responseReceived.toolSource().isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.INTRUDER, ToolType.SCANNER)) {
            executor.submit(() -> processResponse(responseReceived));
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void processResponse(HttpResponseReceived responseReceived) {
        try {
            HttpRequest request = responseReceived.initiatingRequest();
            if (request == null) return;

            String host = request.httpService().host();
            String method = request.method();
            int statusCode = responseReceived.statusCode();

            String contentType = "";
            for (var h : responseReceived.headers()) {
                if (h.name().equalsIgnoreCase("content-type")) {
                    contentType = h.value().toLowerCase();
                    break;
                }
            }

            String body = responseReceived.bodyToString();
            Set<String> extractedPaths = new HashSet<>();

            // ── 1. Ekstrakcja pełnych URLi ───────────────────────────────
            Matcher fullMatcher = FULL_URL_RE.matcher(body);
            while (fullMatcher.find()) {
                try {
                    URL u = new URL(fullMatcher.group());
                    if (u.getHost().equalsIgnoreCase(host)) {
                        extractedPaths.add(u.getPath());
                    }
                } catch (MalformedURLException ignored) {}
            }

            // ── 2. Ekstrakcja ścieżek relatywnych / absolutnych ───────────
            Matcher relMatcher = URL_RE.matcher(body);
            while (relMatcher.find()) {
                String candidate = relMatcher.group(1).trim().replaceAll("[\"']", "");
                if (candidate.startsWith("/")) {
                    extractedPaths.add(candidate.split("\\?")[0]);
                }
            }

            if (contentType.contains("json")) {
                extractJsonPaths(body, extractedPaths);
            }

            for (String p : extractedPaths) {
                String dedupeKey = method + "|" + host + "|" + p;
                if (!seen.add(dedupeKey)) continue;

                HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(request, responseReceived);
                Endpoint ep = new Endpoint(host, method, p, statusCode, reqResp);
                ep.patternGroup = patternMatcher.normalize(p);
                ep.riskScore = riskScorer.score(ep);

                onEndpointFound.accept(ep);
            }

        } catch (Exception e) {
            if (ReconMasterPro.api != null) {
                ReconMasterPro.api.logging().logToError("EndpointDiscovery error: " + e.getMessage());
            }
        }
    }

    private void extractJsonPaths(String json, Set<String> out) {
        Pattern jsonUrl = Pattern.compile(
            "\"(?:url|href|link|endpoint|path|uri)\"\\s*:\\s*\"(/[^\"]+)\"",
            Pattern.CASE_INSENSITIVE
        );
        Matcher m = jsonUrl.matcher(json);
        while (m.find()) {
            out.add(m.group(1));
        }
    }

    private String getContentType(List<String> headers) {
        return headers.stream()
            .filter(h -> h.toLowerCase().startsWith("content-type:"))
            .findFirst()
            .orElse("")
            .toLowerCase();
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
