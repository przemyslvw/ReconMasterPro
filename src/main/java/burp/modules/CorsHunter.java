package burp.modules;

import burp.ReconMasterPro;
import burp.models.CorsFinding;
import burp.utils.CorsAnalyzer;
import burp.utils.CorsPoCGenerator;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

public class CorsHunter extends AbstractReconHandler {

    private static final List<String> PROBE_ORIGINS = List.of(
        "https://evil.attacker.com",
        "null",
        "https://evil.%s",
        "https://%s.evil.attacker.com"
    );

    private final Consumer<CorsFinding> onFinding;
    private final Set<String> probedUrls = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public CorsHunter(Consumer<CorsFinding> onFinding) {
        super("CORS", 2);
        this.onFinding = onFinding;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (isFromAuditableSource(responseReceived.toolSource())) {
            executor.submit(() -> {
                try {
                    HttpRequest request = responseReceived.initiatingRequest();
                    if (request == null) return;

                    String body = responseReceived.bodyToString();
                    if (body == null) return;

                    List<String> rawHeaders = responseReceived.headers().stream().map(h -> h.toString()).toList();
                    Map<String, String> headers = parseHeaders(rawHeaders);

                    if (!headers.containsKey("access-control-allow-origin")) return;

                    String host   = request.httpService().host();
                    String url    = request.url();
                    String method = request.method();

                    Optional<CorsFinding> finding =
                        CorsAnalyzer.analyze(host, url, method, headers, null);

                    finding.ifPresent(f -> {
                        f.originalRequestResponse = HttpRequestResponse.httpRequestResponse(request, responseReceived);
                        f.pocHtml = CorsPoCGenerator.generate(f);
                        onFinding.accept(f);
                    });

                } catch (Exception e) {
                    logError("Passive analysis error: " + e.getMessage());
                }
            });
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    public void probe(String host, String url, String method) {
        String key = method + "|" + url;
        if (!probedUrls.add(key)) return;

        executor.submit(() -> {
            try {
                java.net.URL parsed = new java.net.URL(url);
                int port = parsed.getPort();
                boolean useHttps = parsed.getProtocol().equalsIgnoreCase("https");
                if (port == -1) port = useHttps ? 443 : 80;

                burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(host, port, useHttps);

                for (String originTemplate : PROBE_ORIGINS) {
                    String origin = originTemplate.contains("%s")
                        ? String.format(originTemplate, host)
                        : originTemplate;

                    HttpRequest request = HttpRequest.httpRequest()
                        .withService(service)
                        .withMethod(method)
                        .withPath(parsed.getPath())
                        .withHeader("Host", host)
                        .withHeader("Origin", origin)
                        .withHeader("Accept", "*/*")
                        .withHeader("User-Agent", "Mozilla/5.0")
                        .withHeader("Connection", "close");

                    HttpRequestResponse reqResp = ReconMasterPro.api.http().sendRequest(request);
                    if (reqResp == null || reqResp.response() == null) continue;

                    List<String> rawHeaders = reqResp.response().headers().stream().map(h -> h.toString()).toList();
                    Map<String, String> responseHeaders = parseHeaders(rawHeaders);

                    Optional<CorsFinding> finding =
                        CorsAnalyzer.analyze(host, url, method, responseHeaders, origin);

                    finding.ifPresent(f -> {
                        f.originalRequestResponse = reqResp;
                        f.pocHtml = CorsPoCGenerator.generate(f);
                        onFinding.accept(f);
                    });
                }

            } catch (Exception e) {
                logError("Probe error for " + url + ": " + e.getMessage());
            }
        });
    }

    private Map<String, String> parseHeaders(List<String> rawHeaders) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 1; i < rawHeaders.size(); i++) {
            String line = rawHeaders.get(i);
            int colon = line.indexOf(':');
            if (colon > 0) {
                String name  = line.substring(0, colon).trim().toLowerCase();
                String value = line.substring(colon + 1).trim();
                map.put(name, value);
            }
        }
        return map;
    }
}
