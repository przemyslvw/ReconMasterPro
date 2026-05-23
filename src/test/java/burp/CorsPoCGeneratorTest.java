package burp;

import burp.models.CorsFinding;
import burp.utils.CorsPoCGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CorsPoCGeneratorTest {

    @Test
    void pocForReflectedWithCredentialsContainsFetch() {
        CorsFinding f = new CorsFinding(
            CorsFinding.IssueType.REFLECTED_ORIGIN_CREDENTIALS,
            "example.com", "https://example.com/api/profile", "GET");
        f.responseAcao = "https://evil.attacker.com";
        f.testedOrigin = "https://evil.attacker.com";

        String poc = CorsPoCGenerator.generate(f);

        assertTrue(poc.contains("fetch"), "PoC musi zawierać fetch()");
        assertTrue(poc.contains("https://example.com/api/profile"), "PoC musi zawierać URL celu");
        assertTrue(poc.contains("credentials"), "PoC musi używać credentials");
        assertTrue(poc.contains("<!DOCTYPE html"), "PoC musi być pełnym dokumentem HTML");
    }

    @Test
    void pocForNullOriginContainsSandboxedIframe() {
        CorsFinding f = new CorsFinding(
            CorsFinding.IssueType.NULL_ORIGIN_CREDENTIALS,
            "example.com", "https://example.com/api/admin", "GET");
        f.responseAcao = "null";

        String poc = CorsPoCGenerator.generate(f);

        assertTrue(poc.contains("iframe"), "PoC dla null origin musi używać sandboxed iframe");
        assertTrue(poc.contains("sandbox"), "iframe musi mieć atrybut sandbox");
        assertTrue(poc.contains("https://example.com/api/admin"), "PoC musi zawierać URL celu");
    }

    @Test
    void pocForWildcardContainsFetch() {
        CorsFinding f = new CorsFinding(
            CorsFinding.IssueType.WILDCARD_ORIGIN,
            "example.com", "https://example.com/api/public", "GET");
        f.responseAcao = "*";

        String poc = CorsPoCGenerator.generate(f);

        assertTrue(poc.contains("fetch"), "PoC dla wildcard musi zawierać fetch()");
        assertFalse(poc.contains("credentials: 'include'"),
            "PoC dla wildcard bez ACAC nie powinien używać credentials");
    }

    @Test
    void pocContainsEvidenceComment() {
        CorsFinding f = new CorsFinding(
            CorsFinding.IssueType.REFLECTED_ORIGIN,
            "example.com", "https://example.com/api", "GET");
        f.responseAcao = "https://evil.attacker.com";
        f.testedOrigin = "https://evil.attacker.com";

        String poc = CorsPoCGenerator.generate(f);

        assertTrue(poc.contains("Access-Control-Allow-Origin"),
            "PoC musi zawierać dowód (nagłówek response)");
    }

    @Test
    void generatesValidHtmlForAllTypes() {
        for (CorsFinding.IssueType type : CorsFinding.IssueType.values()) {
            CorsFinding f = new CorsFinding(type, "example.com",
                "https://example.com/api", "GET");
            f.responseAcao = "*";
            String poc = CorsPoCGenerator.generate(f);
            assertNotNull(poc);
            assertFalse(poc.isBlank());
            assertTrue(poc.contains("</html>"), "PoC dla " + type + " musi być zamkniętym HTML");
        }
    }
}
