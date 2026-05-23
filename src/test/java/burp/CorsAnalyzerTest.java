package burp;

import burp.models.CorsFinding;
import burp.utils.CorsAnalyzer;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CorsAnalyzerTest {

    @Test
    void returnsEmptyWhenNoCorsHeaders() {
        Map<String, String> headers = Map.of("Content-Type", "application/json");
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, null);
        assertTrue(result.isEmpty());
    }

    @Test
    void returnsEmptyWhenAcaoAbsent() {
        Map<String, String> headers = Map.of("Access-Control-Allow-Credentials", "true");
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, null);
        assertTrue(result.isEmpty());
    }

    @Test
    void detectsWildcardOrigin() {
        Map<String, String> headers = Map.of("Access-Control-Allow-Origin", "*");
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, null);
        assertTrue(result.isPresent());
        assertEquals(CorsFinding.IssueType.WILDCARD_ORIGIN, result.get().type);
        assertEquals("LOW", result.get().severity);
    }

    @Test
    void detectsCredentialedWildcard() {
        Map<String, String> headers = Map.of(
            "Access-Control-Allow-Origin", "*",
            "Access-Control-Allow-Credentials", "true"
        );
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, null);
        assertTrue(result.isPresent());
        assertEquals(CorsFinding.IssueType.CREDENTIALED_WILDCARD, result.get().type);
        assertEquals("MEDIUM", result.get().severity);
    }

    @Test
    void detectsNullOrigin() {
        Map<String, String> headers = Map.of("Access-Control-Allow-Origin", "null");
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, null);
        assertTrue(result.isPresent());
        assertEquals(CorsFinding.IssueType.NULL_ORIGIN, result.get().type);
        assertEquals("HIGH", result.get().severity);
    }

    @Test
    void detectsNullOriginWithCredentials() {
        Map<String, String> headers = Map.of(
            "Access-Control-Allow-Origin", "null",
            "Access-Control-Allow-Credentials", "true"
        );
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, null);
        assertTrue(result.isPresent());
        assertEquals(CorsFinding.IssueType.NULL_ORIGIN_CREDENTIALS, result.get().type);
        assertEquals("CRITICAL", result.get().severity);
    }

    @Test
    void detectsReflectedOriginWhenAcaoMatchesSentOrigin() {
        Map<String, String> headers = Map.of(
            "Access-Control-Allow-Origin", "https://evil.attacker.com"
        );
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, "https://evil.attacker.com");
        assertTrue(result.isPresent());
        assertEquals(CorsFinding.IssueType.REFLECTED_ORIGIN, result.get().type);
        assertEquals("HIGH", result.get().severity);
        assertEquals("https://evil.attacker.com", result.get().testedOrigin);
    }

    @Test
    void detectsReflectedOriginWithCredentials() {
        Map<String, String> headers = Map.of(
            "Access-Control-Allow-Origin", "https://evil.attacker.com",
            "Access-Control-Allow-Credentials", "true"
        );
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, "https://evil.attacker.com");
        assertTrue(result.isPresent());
        assertEquals(CorsFinding.IssueType.REFLECTED_ORIGIN_CREDENTIALS, result.get().type);
        assertEquals("CRITICAL", result.get().severity);
    }

    @Test
    void noFindingWhenAcaoDoesNotMatchSentOrigin() {
        Map<String, String> headers = Map.of(
            "Access-Control-Allow-Origin", "https://example.com"
        );
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, "https://evil.attacker.com");
        assertTrue(result.isEmpty());
    }

    @Test
    void noFindingWhenAcaoMatchesOwnHost() {
        Map<String, String> headers = Map.of(
            "Access-Control-Allow-Origin", "https://example.com"
        );
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, null);
        assertTrue(result.isEmpty());
    }

    @Test
    void headerNameIsCaseInsensitive() {
        Map<String, String> headers = new HashMap<>();
        headers.put("access-control-allow-origin", "*");
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, null);
        assertTrue(result.isPresent());
        assertEquals(CorsFinding.IssueType.WILDCARD_ORIGIN, result.get().type);
    }

    @Test
    void acaValueCaseInsensitive() {
        Map<String, String> headers = Map.of(
            "Access-Control-Allow-Origin", "null",
            "Access-Control-Allow-Credentials", "True"
        );
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, null);
        assertTrue(result.isPresent());
        assertEquals(CorsFinding.IssueType.NULL_ORIGIN_CREDENTIALS, result.get().type);
    }

    @Test
    void reflectedWithCredentialsTakesPriorityOverWildcard() {
        Map<String, String> headers = Map.of(
            "Access-Control-Allow-Origin", "https://evil.attacker.com",
            "Access-Control-Allow-Credentials", "true"
        );
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api", "GET",
                headers, "https://evil.attacker.com");
        assertEquals(CorsFinding.IssueType.REFLECTED_ORIGIN_CREDENTIALS, result.get().type);
    }

    @Test
    void findingContainsCorrectUrl() {
        Map<String, String> headers = Map.of("Access-Control-Allow-Origin", "*");
        Optional<CorsFinding> result =
            CorsAnalyzer.analyze("example.com", "https://example.com/api/users", "POST",
                headers, null);
        assertEquals("https://example.com/api/users", result.get().url);
        assertEquals("POST", result.get().method);
        assertEquals("*", result.get().responseAcao);
    }
}
