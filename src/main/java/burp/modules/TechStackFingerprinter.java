package burp.modules;

import burp.*;
import burp.models.*;
import burp.utils.CveDatabase;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class TechStackFingerprinter implements IHttpListener {

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
    public void processHttpMessage(int toolFlag, boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {
        if (messageIsRequest) return;

        executor.submit(() -> {
            try {
                IHttpService service = messageInfo.getHttpService();
                String host = service.getHost();

                byte[] response = messageInfo.getResponse();
                if (response == null) return;

                IResponseInfo respInfo = BurpExtender.helpers.analyzeResponse(response);
                List<String> headers = respInfo.getHeaders();

                int bodyOffset = respInfo.getBodyOffset();
                String body = new String(response, bodyOffset, response.length - bodyOffset, "UTF-8");

                List<String> cookies = extractCookieNames(headers);

                List<Technology> found = detect(host, headers, body, cookies);
                found.forEach(tech -> {
                    tech.originalRequestResponse = messageInfo;
                    onTechFound.accept(tech);
                });

            } catch (Exception e) {
                log("Error: " + e.getMessage());
            }
        });
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
        try {
            BurpExtender.callbacks.printOutput("[TechFP] " + msg);
        } catch (Exception ignored) {
            System.out.println("[TechFP] " + msg);
        }
    }
}
