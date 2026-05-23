package burp.modules;

import burp.ReconMasterPro;
import burp.models.*;
import burp.utils.CveDatabase;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ToolType;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TechStackFingerprinter implements HttpHandler {

    private List<TechSignature> signatures = new ArrayList<>();
    private final CveDatabase cveDb;
    private final Consumer<Technology> onTechFound;

    // host|techName → już zgłoszone (deduplikacja)
    private final Set<String> reported = ConcurrentHashMap.newKeySet();

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ReconMaster-TechFP");
        t.setDaemon(true);
        return t;
    });

    public TechStackFingerprinter(Consumer<Technology> onTechFound, CveDatabase cveDb) {
        this.onTechFound = onTechFound;
        this.cveDb = cveDb;
    }

    public void loadSignatures() {
        try (InputStream is = getClass().getResourceAsStream("/tech-signatures.json")) {
            if (is == null) {
                log("tech-signatures.json not found");
                return;
            }
            Type listType = new TypeToken<List<TechSignature>>() {}.getType();
            signatures = new Gson().fromJson(new InputStreamReader(is), listType);
            log("Tech signatures loaded: " + signatures.size());
        } catch (Exception e) {
            log("Failed to load signatures: " + e.getMessage());
        }
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

                    String host = request.httpService().host();

                    String body = responseReceived.bodyToString();
                    if (body == null || body.isBlank()) return;

                    List<String> headers = responseReceived.headers().stream().map(h -> h.toString()).toList();
                    List<String> cookies = extractCookieNames(headers);

                    List<Technology> found = detect(host, headers, body, cookies);
                    found.forEach(tech -> {
                        tech.originalRequestResponse = HttpRequestResponse.httpRequestResponse(request, responseReceived);
                        onTechFound.accept(tech);
                    });

                } catch (Exception e) {
                    log("Error: " + e.getMessage());
                }
            });
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    public List<Technology> detect(String host, List<String> headers,
                            String body, List<String> cookieNames) {
        Map<String, Technology> found = new LinkedHashMap<>();

        for (TechSignature sig : signatures) {
            String version = null;

            // 1. nagłówki HTTP
            for (String pattern : sig.headerPatterns) {
                for (String header : headers) {
                    Matcher m = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE)
                                      .matcher(header);
                    if (m.find()) {
                        if (version == null && m.groupCount() >= 1) {
                            try { version = m.group(1); } catch (Exception ignored) {}
                        }
                        final String v = version;
                        found.merge(sig.name,
                            build(sig, host, v, "header"),
                            (existing, neu) -> merge(existing, neu, v));
                    }
                }
            }

            // 2. body (HTML + JS + JSON)
            for (String pattern : sig.bodyPatterns) {
                Matcher m = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(body);
                if (m.find()) {
                    if (version == null && m.groupCount() >= 1) {
                        try { version = m.group(1); } catch (Exception ignored) {}
                    }
                    final String v = version;
                    found.merge(sig.name,
                        build(sig, host, v, "body"),
                        (existing, neu) -> merge(existing, neu, v));
                }
            }

            // 3. ciasteczka
            for (String pattern : sig.cookiePatterns) {
                Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
                for (String cookie : cookieNames) {
                    if (p.matcher(cookie).find()) {
                        final String v = version;
                        found.merge(sig.name,
                            build(sig, host, v, "cookie"),
                            (existing, neu) -> merge(existing, neu, v));
                        break;
                    }
                }
            }
        }

        // filtruj już zgłoszone, dołącz CVE
        List<Technology> result = new ArrayList<>();
        for (Technology tech : found.values()) {
            String key = tech.host + "|" + tech.name;
            if (reported.add(key)) {
                tech.cves = cveDb.query(tech.name, tech.version);
                result.add(tech);
            }
        }
        return result;
    }

    private Technology build(TechSignature sig, String host, String version, String detectedBy) {
        Technology t = new Technology(sig.name, sig.category, host);
        t.version = version;
        t.detectedBy = detectedBy;
        t.confidence = 50;
        return t;
    }

    private Technology merge(Technology existing, Technology neu, String version) {
        existing.confidence = Math.min(100, existing.confidence + 25);
        if (existing.version == null && version != null) existing.version = version;
        return existing;
    }

    private List<String> extractCookieNames(List<String> headers) {
        List<String> names = new ArrayList<>();
        for (String header : headers) {
            if (header.toLowerCase().startsWith("set-cookie:")) {
                String value = header.substring("set-cookie:".length()).trim();
                String name = value.split("=")[0].trim();
                names.add(name);
            }
        }
        return names;
    }

    public void shutdown() { executor.shutdownNow(); }

    private void log(String msg) {
        if (ReconMasterPro.api != null) {
            ReconMasterPro.api.logging().logToOutput("[TechFP] " + msg);
        } else {
            System.out.println("[TechFP] " + msg);
        }
    }
}
