package burp.modules;

import burp.models.*;
import burp.utils.SettingsManager;

import java.util.*;
import java.util.function.Supplier;
import java.util.regex.Pattern;

public class AiAnalyzer {

    private final SettingsManager settings;
    private final Supplier<List<Endpoint>> endpointSupplier;
    private final Supplier<List<Technology>> techSupplier;
    private final Supplier<List<Secret>> secretSupplier;
    private final Supplier<List<CorsFinding>> corsSupplier;
    private final Supplier<List<CloudAsset>> cloudSupplier;
    private final Supplier<List<GraphQLEndpoint>> graphqlSupplier;

    public AiAnalyzer(
            SettingsManager settings,
            Supplier<List<Endpoint>> endpointSupplier,
            Supplier<List<Technology>> techSupplier,
            Supplier<List<Secret>> secretSupplier,
            Supplier<List<CorsFinding>> corsSupplier,
            Supplier<List<CloudAsset>> cloudSupplier,
            Supplier<List<GraphQLEndpoint>> graphqlSupplier) {
        this.settings = settings;
        this.endpointSupplier = endpointSupplier;
        this.techSupplier = techSupplier;
        this.secretSupplier = secretSupplier;
        this.corsSupplier = corsSupplier;
        this.cloudSupplier = cloudSupplier;
        this.graphqlSupplier = graphqlSupplier;
    }

    /**
     * Builds the system prompt describing the expert pentester role and expected output format.
     */
    public String buildSystemPrompt() {
        return "You are an expert cybersecurity pentester and security researcher.\n" +
               "Analyze the target's attack surface based on the security findings and reconnaissance data provided below.\n" +
               "Your task is to identify potential vulnerabilities, assess the risk, and recommend specific, actionable exploitation steps and commands.\n\n" +
               "Format your output in Markdown with the following headings:\n" +
               "# Podsumowanie ryzyka (Risk Summary)\n" +
               "Provide a high-level summary of the target's attack surface and overall security posture.\n\n" +
               "# Rekomendowane ataki (Recommended Attack Paths)\n" +
               "Provide concrete attack paths and vulnerability assessments based on the gathered findings (CORS, Secrets, GraphQL, Cloud Assets, etc.).\n\n" +
               "# Przykładowe polecenia / POC (PoC Commands & Scripts)\n" +
               "Provide specific, ready-to-run PoC commands (e.g. curl, python scripts, nmap commands) to verify and exploit the potential issues. Ensure any hostnames or secrets are replaced consistently with the masked values provided.";
    }

    /**
     * Aggregates findings and generates the user prompt (payload).
     * Automatically applies OpSec domain masking and secret masking if configured.
     */
    public String buildUserPrompt() {
        boolean maskDomains = settings.isAiMaskDomains();
        boolean maskSecrets = settings.isAiMaskSecrets();

        Map<String, String> hostMap = maskDomains ? buildOpSecHostMap() : Collections.emptyMap();

        StringBuilder sb = new StringBuilder();
        sb.append("# Target Reconnaissance & Security Findings Report\n\n");

        // --- Host mapping table for reference, only if domains are masked ---
        if (maskDomains && !hostMap.isEmpty()) {
            sb.append("## Target Host Mappings (Sanitized)\n");
            sb.append("| Original Target | Masked Reference |\n");
            sb.append("|---|---|\n");
            // Sort by original name for clean display
            List<String> keys = new ArrayList<>(hostMap.keySet());
            Collections.sort(keys);
            for (String k : keys) {
                sb.append("| ").append(k).append(" | ").append(hostMap.get(k)).append(" |\n");
            }
            sb.append("\n");
        }

        // --- Section 1: Technologies & CVEs ---
        sb.append("## 🛠️ Detected Technologies & CVEs\n");
        List<Technology> techs = techSupplier != null ? techSupplier.get() : null;
        if (techs == null || techs.isEmpty()) {
            sb.append("No technologies detected.\n\n");
        } else {
            for (Technology t : techs) {
                String tName = maskDomains ? maskText(t.name, hostMap) : t.name;
                String tVersion = t.version != null ? t.version : "Unknown";
                String tCategory = t.category != null ? t.category : "General";
                String tHost = maskDomains ? maskText(t.host, hostMap) : t.host;
                sb.append(String.format("### %s %s (Host: %s, Category: %s)\n", tName, tVersion, tHost, tCategory));
                if (t.cves != null && !t.cves.isEmpty()) {
                    sb.append("| CVE ID | CVSS | Severity | Description |\n");
                    sb.append("|---|---|---|---|\n");
                    for (CveEntry c : t.cves) {
                        String cDesc = maskDomains ? maskText(c.description, hostMap) : c.description;
                        sb.append(String.format("| %s | %.1f | %s | %s |\n", c.cve_id, c.cvss, c.severity, cDesc));
                    }
                } else {
                    sb.append("No known CVEs associated in local DB.\n");
                }
                sb.append("\n");
            }
        }

        // --- Section 2: Endpoints ---
        sb.append("## 🔗 Endpoints\n");
        List<Endpoint> endpoints = getInterestingEndpoints();
        if (endpoints.isEmpty()) {
            sb.append("No endpoints discovered.\n\n");
        } else {
            sb.append("| Method | Path | Status Code | Risk Score | Host |\n");
            sb.append("|---|---|---|---|---|\n");
            for (Endpoint e : endpoints) {
                String eHost = maskDomains ? maskText(e.host, hostMap) : e.host;
                String ePath = maskDomains ? maskText(e.path, hostMap) : e.path;
                sb.append(String.format("| %s | %s | %d | %d | %s |\n", e.method, ePath, e.statusCode, e.riskScore, eHost));
            }
            sb.append("\n");
        }

        // --- Section 3: CORS Findings ---
        sb.append("## 🌐 CORS Misconfigurations\n");
        List<CorsFinding> cors = corsSupplier != null ? corsSupplier.get() : null;
        if (cors == null || cors.isEmpty()) {
            sb.append("No CORS misconfigurations detected.\n\n");
        } else {
            sb.append("| Host | Method | URL | Issue Type | Severity | Tested Origin | ACAO | ACAC |\n");
            sb.append("|---|---|---|---|---|---|---|---|\n");
            for (CorsFinding c : cors) {
                String cHost = maskDomains ? maskText(c.host, hostMap) : c.host;
                String cUrl = maskDomains ? maskText(c.url, hostMap) : c.url;
                String cOrigin = maskDomains ? maskText(c.testedOrigin, hostMap) : c.testedOrigin;
                String cAcao = maskDomains ? maskText(c.responseAcao, hostMap) : c.responseAcao;
                String cAcac = maskDomains ? maskText(c.responseAcac, hostMap) : c.responseAcac;
                sb.append(String.format("| %s | %s | %s | %s | %s | %s | %s | %s |\n",
                        cHost, c.method, cUrl, c.type.name(), c.severity, cOrigin, cAcao, cAcac));
            }
            sb.append("\n");
        }

        // --- Section 4: GraphQL Endpoints ---
        sb.append("## 📊 GraphQL Endpoints\n");
        List<GraphQLEndpoint> gqls = graphqlSupplier != null ? graphqlSupplier.get() : null;
        if (gqls == null || gqls.isEmpty()) {
            sb.append("No GraphQL endpoints detected.\n\n");
        } else {
            sb.append("| Host | URL | Detection Method | Introspection Enabled | Schema Loaded |\n");
            sb.append("|---|---|---|---|---|\n");
            for (GraphQLEndpoint g : gqls) {
                String gHost = maskDomains ? maskText(g.host, hostMap) : g.host;
                String gUrl = maskDomains ? maskText(g.url, hostMap) : g.url;
                sb.append(String.format("| %s | %s | %s | %b | %b |\n",
                        gHost, gUrl, g.detectionMethod, g.introspectionEnabled, g.schemaLoaded));
            }
            sb.append("\n");
        }

        // --- Section 5: Cloud Assets ---
        sb.append("## ☁️ Cloud Assets\n");
        List<CloudAsset> clouds = cloudSupplier != null ? cloudSupplier.get() : null;
        if (clouds == null || clouds.isEmpty()) {
            sb.append("No cloud assets detected.\n\n");
        } else {
            sb.append("| Provider | Bucket/Account | URL | Source URL | Source Type | Access Status | HTTP Code |\n");
            sb.append("|---|---|---|---|---|---|---|\n");
            for (CloudAsset c : clouds) {
                String cBucket = maskDomains ? maskText(c.bucketOrAccount, hostMap) : c.bucketOrAccount;
                String cUrl = maskDomains ? maskText(c.url, hostMap) : c.url;
                String cSource = maskDomains ? maskText(c.sourceUrl, hostMap) : c.sourceUrl;
                sb.append(String.format("| %s | %s | %s | %s | %s | %s | %d |\n",
                        c.provider.name(), cBucket, cUrl, cSource, c.sourceType, c.accessStatus, c.accessStatusCode));
            }
            sb.append("\n");
        }

        // --- Section 6: Secrets ---
        sb.append("## 🔑 Discovered Secrets\n");
        List<Secret> secrets = secretSupplier != null ? secretSupplier.get() : null;
        if (secrets == null || secrets.isEmpty()) {
            sb.append("No secrets detected.\n\n");
        } else {
            sb.append("| Type | Severity | Value | Host | URL | Detected By | Context |\n");
            sb.append("|---|---|---|---|---|---|---|\n");
            for (Secret s : secrets) {
                String sHost = maskDomains ? maskText(s.host, hostMap) : s.host;
                String sUrl = maskDomains ? maskText(s.url, hostMap) : s.url;
                String sVal = maskSecrets ? s.value : s.fullValue;
                if (maskDomains) {
                    sVal = maskText(sVal, hostMap);
                    sUrl = maskText(sUrl, hostMap);
                }
                String sCtx = maskDomains ? maskText(s.context, hostMap) : s.context;
                sCtx = sCtx.replace("|", "\\|").replace("\n", " ").replace("\r", " ");
                sb.append(String.format("| %s | %s | %s | %s | %s | %s | %s |\n",
                        s.type, s.severity, sVal, sHost, sUrl, s.detectedBy, sCtx));
            }
            sb.append("\n");
        }

        return sb.toString();
    }

    /**
     * Gathers all unique hosts from all data sources to build an OpSec host mapping dictionary.
     */
    public Map<String, String> buildOpSecHostMap() {
        Set<String> uniqueHosts = new HashSet<>();

        if (endpointSupplier != null && endpointSupplier.get() != null) {
            for (Endpoint e : endpointSupplier.get()) {
                if (e.host != null && !e.host.trim().isEmpty()) {
                    uniqueHosts.add(e.host.trim().toLowerCase());
                }
            }
        }
        if (techSupplier != null && techSupplier.get() != null) {
            for (Technology t : techSupplier.get()) {
                if (t.host != null && !t.host.trim().isEmpty()) {
                    uniqueHosts.add(t.host.trim().toLowerCase());
                }
            }
        }
        if (secretSupplier != null && secretSupplier.get() != null) {
            for (Secret s : secretSupplier.get()) {
                if (s.host != null && !s.host.trim().isEmpty()) {
                    uniqueHosts.add(s.host.trim().toLowerCase());
                }
            }
        }
        if (corsSupplier != null && corsSupplier.get() != null) {
            for (CorsFinding c : corsSupplier.get()) {
                if (c.host != null && !c.host.trim().isEmpty()) {
                    uniqueHosts.add(c.host.trim().toLowerCase());
                }
            }
        }
        if (graphqlSupplier != null && graphqlSupplier.get() != null) {
            for (GraphQLEndpoint g : graphqlSupplier.get()) {
                if (g.host != null && !g.host.trim().isEmpty()) {
                    uniqueHosts.add(g.host.trim().toLowerCase());
                }
            }
        }
        if (cloudSupplier != null && cloudSupplier.get() != null) {
            for (CloudAsset c : cloudSupplier.get()) {
                if (c.bucketOrAccount != null && !c.bucketOrAccount.trim().isEmpty()) {
                    uniqueHosts.add(c.bucketOrAccount.trim().toLowerCase());
                }
                String h = extractHost(c.url);
                if (h != null) uniqueHosts.add(h);
                String sh = extractHost(c.sourceUrl);
                if (sh != null) uniqueHosts.add(sh);
            }
        }

        Map<String, String> hostMap = new HashMap<>();
        int ipCounter = 1;
        int domainCounter = 1;

        List<String> sortedUnique = new ArrayList<>(uniqueHosts);
        Collections.sort(sortedUnique);

        for (String host : sortedUnique) {
            if (isIpAddress(host)) {
                hostMap.put(host, "10.0.0." + ipCounter++);
            } else {
                hostMap.put(host, "target-" + domainCounter++ + ".local");
            }
        }

        return hostMap;
    }

    /**
     * Consistent replacement of matched domains/IPs, sorted by descending key length.
     */
    public String maskText(String text, Map<String, String> hostMap) {
        if (text == null || text.isEmpty() || hostMap == null || hostMap.isEmpty()) {
            return text;
        }

        List<String> sortedKeys = new ArrayList<>(hostMap.keySet());
        sortedKeys.sort((a, b) -> Integer.compare(b.length(), a.length()));

        String masked = text;
        for (String key : sortedKeys) {
            String value = hostMap.get(key);
            masked = Pattern.compile(Pattern.quote(key), Pattern.CASE_INSENSITIVE)
                            .matcher(masked)
                            .replaceAll(value);
        }
        return masked;
    }

    private List<Endpoint> getInterestingEndpoints() {
        if (endpointSupplier == null || endpointSupplier.get() == null) {
            return Collections.emptyList();
        }
        List<Endpoint> all = new ArrayList<>(endpointSupplier.get());
        all.sort((a, b) -> Integer.compare(b.riskScore, a.riskScore));
        if (all.size() > 100) {
            return all.subList(0, 100);
        }
        return all;
    }

    private String extractHost(String urlStr) {
        if (urlStr == null || urlStr.trim().isEmpty()) return null;
        try {
            String host = urlStr;
            int doubleSlash = host.indexOf("://");
            if (doubleSlash != -1) {
                host = host.substring(doubleSlash + 3);
            }
            int slash = host.indexOf("/");
            if (slash != -1) {
                host = host.substring(0, slash);
            }
            int colon = host.indexOf(":");
            if (colon != -1) {
                host = host.substring(0, colon);
            }
            int question = host.indexOf("?");
            if (question != -1) {
                host = host.substring(0, question);
            }
            host = host.trim().toLowerCase();
            return host.isEmpty() ? null : host;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isIpAddress(String host) {
        if (host == null) return false;
        if (host.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            return true;
        }
        return host.contains(":");
    }
}
