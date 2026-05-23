package burp.modules;

import burp.*;
import burp.models.CorsFinding;
import burp.utils.CorsAnalyzer;
import burp.utils.CorsPoCGenerator;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

public class CorsHunter implements IHttpListener {

    private static final List<String> PROBE_ORIGINS = List.of(
        "https://evil.attacker.com",
        "null",
        "https://evil.%s",
        "https://%s.evil.attacker.com"
    );

    private final Consumer<CorsFinding> onFinding;
    private final ExecutorService executor = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "ReconMaster-CORS");
        t.setDaemon(true);
        return t;
    });
    private final Set<String> probedUrls = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public CorsHunter(Consumer<CorsFinding> onFinding) {
        this.onFinding = onFinding;
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
                Map<String, String> headers = parseHeaders(respInfo.getHeaders());

                if (!headers.containsKey("access-control-allow-origin")) return;

                IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(messageInfo);
                IHttpService service = messageInfo.getHttpService();
                String host   = service.getHost();
                String url    = reqInfo.getUrl().toString();
                String method = reqInfo.getMethod();

                Optional<CorsFinding> finding =
                    CorsAnalyzer.analyze(host, url, method, headers, null);

                finding.ifPresent(f -> {
                    f.originalRequestResponse = messageInfo;
                    f.pocHtml = CorsPoCGenerator.generate(f);
                    onFinding.accept(f);
                });

            } catch (Exception e) {
                logError("Passive analysis error: " + e.getMessage());
            }
        });
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

                IHttpService service = BurpExtender.helpers.buildHttpService(
                    host, port, useHttps);

                for (String originTemplate : PROBE_ORIGINS) {
                    String origin = originTemplate.contains("%s")
                        ? String.format(originTemplate, host)
                        : originTemplate;

                    byte[] request = buildRequest(parsed.getPath(), host, method, origin);
                    IHttpRequestResponse reqResp = BurpExtender.callbacks.makeHttpRequest(service, request);
                    if (reqResp == null || reqResp.getResponse() == null) continue;

                    IResponseInfo respInfo = BurpExtender.helpers.analyzeResponse(reqResp.getResponse());
                    Map<String, String> responseHeaders = parseHeaders(respInfo.getHeaders());

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

    private byte[] buildRequest(String path, String host, String method, String origin) {
        List<String> headers = new ArrayList<>(List.of(
            method + " " + path + " HTTP/1.1",
            "Host: " + host,
            "Origin: " + origin,
            "Accept: */*",
            "User-Agent: Mozilla/5.0",
            "Connection: close"
        ));
        return BurpExtender.helpers.buildHttpMessage(headers, null);
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

    public void shutdown() {
        executor.shutdownNow();
    }

    private void logError(String msg) {
        try { BurpExtender.callbacks.printError("[CORS] " + msg); }
        catch (Exception ignored) { System.err.println("[CORS] " + msg); }
    }
}
