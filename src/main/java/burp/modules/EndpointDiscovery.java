package burp.modules;

import burp.*;
import burp.models.Endpoint;
import burp.utils.PatternMatcher;
import burp.utils.RiskScorer;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.*;

public class EndpointDiscovery implements IHttpListener {

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
    public void processHttpMessage(int toolFlag, boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {
        if (messageIsRequest) return;
        executor.submit(() -> processResponse(messageInfo));
    }

    private void processResponse(IHttpRequestResponse messageInfo) {
        try {
            IHttpService service = messageInfo.getHttpService();
            String host = service.getHost();

            IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(messageInfo);
            String method = reqInfo.getMethod();

            byte[] response = messageInfo.getResponse();
            if (response == null) return;

            IResponseInfo respInfo = BurpExtender.helpers.analyzeResponse(response);
            int statusCode = respInfo.getStatusCode();

            int bodyOffset = respInfo.getBodyOffset();
            String body = new String(response, bodyOffset, response.length - bodyOffset, "UTF-8");

            String contentType = getContentType(respInfo.getHeaders());

            Set<String> extractedPaths = new HashSet<>();

            Matcher fullMatcher = FULL_URL_RE.matcher(body);
            while (fullMatcher.find()) {
                try {
                    URL u = new URL(fullMatcher.group());
                    if (u.getHost().equalsIgnoreCase(host)) {
                        extractedPaths.add(u.getPath());
                    }
                } catch (MalformedURLException ignored) {}
            }

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

            for (String path : extractedPaths) {
                String dedupeKey = method + "|" + host + "|" + path;
                if (!seen.add(dedupeKey)) continue;

                Endpoint ep = new Endpoint(host, method, path, statusCode);
                ep.patternGroup = patternMatcher.normalize(path);
                ep.riskScore = riskScorer.score(ep);

                onEndpointFound.accept(ep);
            }

        } catch (Exception e) {
            BurpExtender.callbacks.printError("EndpointDiscovery error: " + e.getMessage());
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
