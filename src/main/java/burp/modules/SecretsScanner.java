package burp.modules;

import burp.*;
import burp.models.Secret;
import burp.models.SecretPattern;
import burp.utils.EntropyCalculator;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecretsScanner implements IHttpListener {

    // ── Wzorce regex — kolejność: od najpoważniejszych ────────────────
    private static final List<SecretPattern> PATTERNS = List.of(

        // Klucze prywatne — CRITICAL
        new SecretPattern("RSA Private Key",
            "-----BEGIN RSA PRIVATE KEY-----",
            "CRITICAL", 0),
        new SecretPattern("EC Private Key",
            "-----BEGIN EC PRIVATE KEY-----",
            "CRITICAL", 0),
        new SecretPattern("Private Key (generic)",
            "-----BEGIN PRIVATE KEY-----",
            "CRITICAL", 0),
        new SecretPattern("OpenSSH Private Key",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "CRITICAL", 0),

        // AWS — CRITICAL
        new SecretPattern("AWS Access Key ID",
            "(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
            "CRITICAL", 1),
        new SecretPattern("AWS Secret Access Key",
            "(?i)aws[_\\-\\s.]*secret[_\\-\\s.]*(?:access[_\\-\\s.]*)?key[\"'\\s]*[=:][\"'\\s]*([a-zA-Z0-9+/]{40})",
            "CRITICAL", 1),

        // Stripe live — CRITICAL
        new SecretPattern("Stripe Live Key",
            "(sk_live_[a-zA-Z0-9]{24,})",
            "CRITICAL", 1),

        // GitHub — HIGH
        new SecretPattern("GitHub Personal Access Token",
            "(ghp_[a-zA-Z0-9]{36})",
            "HIGH", 1),
        new SecretPattern("GitHub OAuth Token",
            "(gho_[a-zA-Z0-9]{36})",
            "HIGH", 1),
        new SecretPattern("GitHub App Token",
            "(ghs_[a-zA-Z0-9]{36})",
            "HIGH", 1),
        new SecretPattern("GitHub Fine-grained Token",
            "(github_pat_[a-zA-Z0-9_]{82})",
            "HIGH", 1),

        // Google — HIGH
        new SecretPattern("Google API Key",
            "(AIza[0-9A-Za-z\\-_]{35})",
            "HIGH", 1),
        new SecretPattern("Google OAuth Client Secret",
            "(GOCSPX-[a-zA-Z0-9_\\-]{28})",
            "HIGH", 1),

        // Slack — HIGH
        new SecretPattern("Slack Token",
            "(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})",
            "HIGH", 1),
        new SecretPattern("Slack Webhook",
            "(https://hooks\\.slack\\.com/services/T[a-zA-Z0-9]{8}/B[a-zA-Z0-9]{8,10}/[a-zA-Z0-9]{24})",
            "HIGH", 1),

        // Stripe test — MEDIUM (niżej niż live)
        new SecretPattern("Stripe Test Key",
            "(sk_test_[a-zA-Z0-9]{24,})",
            "MEDIUM", 1),
        new SecretPattern("Stripe Publishable Key",
            "(pk_live_[a-zA-Z0-9]{24,})",
            "MEDIUM", 1),

        // JWT — MEDIUM
        new SecretPattern("JWT",
            "(eyJ[a-zA-Z0-9+/=_\\-]{8,}\\.[a-zA-Z0-9+/=_\\-]{8,}\\.[a-zA-Z0-9+/=_\\-]{8,})",
            "MEDIUM", 1),

        // Credentiale w URL — MEDIUM
        new SecretPattern("Credentials in URL",
            "(https?://[^:@\\s]+:[^@\\s]{4,}@[^\\s\"'<>]+)",
            "MEDIUM", 1),

        // Connection strings — MEDIUM
        new SecretPattern("MongoDB Connection String",
            "(mongodb(?:\\+srv)?://[^:]+:[^@]{4,}@[^\\s\"'<>]+)",
            "MEDIUM", 1),
        new SecretPattern("PostgreSQL Connection String",
            "(postgres(?:ql)?://[^:]+:[^@]{4,}@[^\\s\"'<>]+)",
            "MEDIUM", 1),

        // Generic Bearer — LOW (wysokie FP, ostatni)
        new SecretPattern("Bearer Token",
            "(?i)Authorization:\\s*Bearer\\s+([a-zA-Z0-9+/=_\\-\\.]{30,})",
            "LOW", 1)
    );

    // Wzorzec entropijny: słowo kluczowe + wartość w cudzysłowie/po =/:
    private static final Pattern ENTROPY_CONTEXT_RE = Pattern.compile(
        "(?i)(?:api[_\\-]?key|secret[_\\-]?key|access[_\\-]?token|auth[_\\-]?token|" +
        "private[_\\-]?key|api[_\\-]?secret|client[_\\-]?secret|webhook[_\\-]?secret)" +
        "[\"'\\s]*[=:][\"'\\s]*([\"']?)([a-zA-Z0-9+/=_\\-\\.]{20,128})\\1"
    );

    private static final double ENTROPY_THRESHOLD = 4.5;
    private static final int CONTEXT_RADIUS = 60;

    // deduplikacja: host|type|redacted_value
    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    private final Consumer<Secret> onSecretFound;

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ReconMaster-Secrets");
        t.setDaemon(true);
        return t;
    });

    public SecretsScanner(Consumer<Secret> onSecretFound) {
        this.onSecretFound = onSecretFound;
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

                // skanuj tylko tekstowe odpowiedzi
                String contentType = respInfo.getHeaders().stream()
                    .filter(h -> h.toLowerCase().startsWith("content-type:"))
                    .findFirst().orElse("").toLowerCase();
                if (!isTextualContent(contentType)) return;

                int bodyOffset = respInfo.getBodyOffset();
                String body = new String(response, bodyOffset,
                    response.length - bodyOffset, "UTF-8");

                String url = BurpExtender.helpers.analyzeRequest(messageInfo)
                    .getUrl().toString();

                List<Secret> found = scan(host, url, body);
                found.forEach(s -> {
                    String key = s.host + "|" + s.type + "|" + s.value;
                    if (seen.add(key)) onSecretFound.accept(s);
                });

            } catch (Exception e) {
                try {
                    BurpExtender.callbacks.printError("SecretsScanner: " + e.getMessage());
                } catch (Exception ignored) {}
            }
        });
    }

    public List<Secret> scan(String host, String url, String body) {
        List<Secret> results = new ArrayList<>();

        // 1. Regex patterns
        for (SecretPattern sp : PATTERNS) {
            Matcher m = sp.pattern.matcher(body);
            while (m.find()) {
                String value;
                try {
                    value = sp.captureGroup == 0 ? m.group() : m.group(sp.captureGroup);
                } catch (IndexOutOfBoundsException e) {
                    value = m.group();
                }
                if (value == null || value.isEmpty()) continue;
                if (isFiltered(value)) continue;

                String context = extractContext(body, m.start(), m.end());
                double entropy = EntropyCalculator.calculate(value);

                Secret secret = new Secret(sp.name, sp.severity, value,
                    context, host, url, "regex");
                secret.entropy = entropy;
                results.add(secret);
            }
        }

        // 2. Entropy + kontekst
        Matcher em = ENTROPY_CONTEXT_RE.matcher(body);
        while (em.find()) {
            String value = em.group(2);
            if (value == null || value.isEmpty()) continue;
            if (isFiltered(value)) continue;

            double entropy = EntropyCalculator.calculate(value);
            if (entropy < ENTROPY_THRESHOLD) continue;

            // sprawdź, czy to nie zostało już złapane przez regex
            String redacted = new Secret("", "", value, "", "", "", "").value;
            boolean alreadyCaught = results.stream()
                .anyMatch(s -> s.value.equals(redacted));
            if (alreadyCaught) continue;

            String context = extractContext(body, em.start(), em.end());
            Secret secret = new Secret("High-Entropy Secret", "MEDIUM", value,
                context, host, url, "entropy");
            secret.entropy = entropy;
            results.add(secret);
        }

        return results;
    }

    // ── Filtry false-positive ─────────────────────────────────────────

    private static final List<String> PLACEHOLDER_SUBSTRINGS = List.of(
        "example", "your_", "your-", "<your", "placeholder", "dummy",
        "sample", "test", "fake", "changeme", "replace", "insert",
        "xxxxxxxx", "00000000", "11111111", "aaaaaaaaa"
    );

    private boolean isFiltered(String value) {
        if (value.length() < 8) return true;

        String lower = value.toLowerCase();

        // Nie filtruj znanych formatów sekretów (nawet jeśli zawierają słowa kluczowe)
        if (lower.startsWith("sk_live_") || lower.startsWith("sk_test_") ||
            lower.startsWith("pk_live_") || lower.startsWith("pk_test_")) {
            return false;
        }

        for (String p : PLACEHOLDER_SUBSTRINGS) {
            if (lower.contains(p)) return true;
        }

        // monotypowe ciągi: "aaaa", "1111"
        if (value.chars().distinct().count() <= 2) return true;

        // CSS hex kolor: #RRGGBB lub #RGB
        if (value.matches("#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?")) return true;

        // URL — prawdopodobnie endpoint, nie sekret
        if (value.startsWith("http://") || value.startsWith("https://")) return false;

        return false;
    }

    private String extractContext(String body, int start, int end) {
        int from = Math.max(0, start - CONTEXT_RADIUS);
        int to   = Math.min(body.length(), end + CONTEXT_RADIUS);
        String raw = body.substring(from, to)
            .replaceAll("\\s+", " ")
            .trim();
        if (from > 0)           raw = "..." + raw;
        if (to < body.length()) raw = raw + "...";
        return raw;
    }

    private boolean isTextualContent(String contentType) {
        return contentType.contains("text") ||
               contentType.contains("javascript") ||
               contentType.contains("json") ||
               contentType.contains("xml") ||
               contentType.isEmpty(); // nieznany — skanuj dla bezpieczeństwa
    }

    public void shutdown() { executor.shutdownNow(); }
}
