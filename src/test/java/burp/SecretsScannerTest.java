package burp;

import burp.models.Secret;
import burp.modules.SecretsScanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class SecretsScannerTest {

    private SecretsScanner scanner;

    @BeforeEach
    void setup() {
        scanner = new SecretsScanner(secret -> {});
    }

    // ── Regex detekcja ────────────────────────────────────────────────

    @Test
    void detectsAwsAccessKey() {
        String body = "config.aws_key = 'AKIAIOSFODNN7REALKEY';";
        List<Secret> found = scanner.scan("example.com", "/app.js", body);
        assertTrue(found.stream().anyMatch(s -> s.type.contains("AWS")));
    }

    @Test
    void detectsGitHubToken() {
        String body = "Authorization: Bearer ghp_16C7e42F292c6912E7710c838347Ae178B4a";
        List<Secret> found = scanner.scan("example.com", "/config.js", body);
        assertTrue(found.stream().anyMatch(s -> s.type.contains("GitHub")));
    }

    @Test
    void detectsJwt() {
        String body = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        List<Secret> found = scanner.scan("example.com", "/auth", body);
        assertTrue(found.stream().anyMatch(s -> s.type.equals("JWT")));
    }

    @Test
    void detectsPrivateKey() {
        String body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...";
        List<Secret> found = scanner.scan("example.com", "/cert.pem", body);
        assertTrue(found.stream().anyMatch(s -> s.severity.equals("CRITICAL")));
    }

    @Test
    void detectsStripeLiveKey() {
        String body = "const stripe = require('stripe')('sk_live_4eC39HqLyjWDarjtT1zdp7dc');";
        List<Secret> found = scanner.scan("example.com", "/payment.js", body);
        Secret s = found.stream().filter(x -> x.type.contains("Stripe")).findFirst().orElse(null);
        assertNotNull(s);
        assertEquals("CRITICAL", s.severity);
    }

    @Test
    void stripeTestKeyIsLowerSeverity() {
        String body = "const key = 'sk_test_4eC39HqLyjWDarjtT1zdp7dc';";
        List<Secret> found = scanner.scan("example.com", "/payment.js", body);
        Secret s = found.stream().filter(x -> x.type.contains("Stripe")).findFirst().orElse(null);
        assertNotNull(s);
        assertNotEquals("CRITICAL", s.severity);
    }

    // ── Context-aware filtering ───────────────────────────────────────

    @Test
    void ignoresExampleAwsKey() {
        // oficjalny przykład z dokumentacji AWS — nie jest prawdziwym kluczem
        String body = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        List<Secret> found = scanner.scan("example.com", "/readme.html", body);
        assertTrue(found.stream().noneMatch(s -> s.type.contains("AWS")),
            "EXAMPLE key nie powinien być flagowany");
    }

    @Test
    void ignoresPlaceholderValues() {
        String body = "api_key = 'your_api_key_here'";
        List<Secret> found = scanner.scan("example.com", "/docs.html", body);
        assertTrue(found.isEmpty());
    }

    @Test
    void ignoresXxxPlaceholders() {
        String body = "token = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'";
        List<Secret> found = scanner.scan("example.com", "/config.js", body);
        assertTrue(found.isEmpty());
    }

    // ── Entropy detekcja ─────────────────────────────────────────────

    @Test
    void detectsHighEntropyApiKeyByContext() {
        // brak pasującego regex, ale "api_key=" + wysoka entropia
        String body = "api_key = \"wJalrXUtnFEMIK7MDENGbPxRfiCYREALKEY123\"";
        List<Secret> found = scanner.scan("example.com", "/config.js", body);
        assertTrue(found.stream().anyMatch(s -> s.detectedBy.equals("entropy")));
    }

    @Test
    void doesNotFlagLowEntropyContextualValue() {
        // kontekst jest, ale wartość niska entropia → nie flaguj
        String body = "api_key = \"development\"";
        List<Secret> found = scanner.scan("example.com", "/config.js", body);
        assertTrue(found.stream().noneMatch(s -> s.detectedBy.equals("entropy")));
    }

    // ── Severity i redakcja ───────────────────────────────────────────

    @Test
    void secretValueIsRedacted() {
        String body = "const key = 'AKIAIOSFODNN7HFXJMYQ';";
        List<Secret> found = scanner.scan("example.com", "/app.js", body);
        assertFalse(found.isEmpty());
        Secret s = found.get(0);
        assertTrue(s.value.contains("..."), "Wartość powinna być zredagowana: " + s.value);
        assertFalse(s.value.equals(s.fullValue));
    }

    @Test
    void contextIsExtracted() {
        String body = "let secret = 'AKIAIOSFODNN7HFXJMYQ'; // aws key";
        List<Secret> found = scanner.scan("example.com", "/app.js", body);
        assertFalse(found.isEmpty());
        assertFalse(found.get(0).context.isEmpty());
    }
}
