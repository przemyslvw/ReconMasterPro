package burp;

import burp.models.Technology;
import burp.modules.TechStackFingerprinter;
import burp.utils.CveDatabase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TechStackFingerprinterTest {

    private TechStackFingerprinter fingerprinter;

    @BeforeEach
    void setup() {
        CveDatabase cveDb = new CveDatabase();
        cveDb.load();
        fingerprinter = new TechStackFingerprinter(tech -> {}, cveDb);
        fingerprinter.loadSignatures();
    }

    @Test
    void detectsJQueryFromScriptTag() {
        String body = "<script src='/js/jquery-3.3.1.min.js'></script>";
        List<Technology> result = fingerprinter.detect("example.com",
            List.of("Content-Type: text/html"), body, List.of());
        assertTrue(result.stream().anyMatch(t -> t.name.equals("jQuery")));
    }

    @Test
    void extractsJQueryVersion() {
        String body = "<script src='/assets/jquery-1.9.0.min.js'></script>";
        List<Technology> result = fingerprinter.detect("example.com",
            List.of("Content-Type: text/html"), body, List.of());
        Technology jquery = result.stream()
            .filter(t -> t.name.equals("jQuery")).findFirst().orElse(null);
        assertNotNull(jquery);
        assertEquals("1.9.0", jquery.version);
    }

    @Test
    void detectsWordPressFromMetaTag() {
        String body = "<meta name=\"generator\" content=\"WordPress 6.1.1\">";
        List<Technology> result = fingerprinter.detect("example.com",
            List.of("Content-Type: text/html"), body, List.of());
        assertTrue(result.stream().anyMatch(t -> t.name.equals("WordPress")));
    }

    @Test
    void detectsPhpFromHeader() {
        List<String> headers = List.of(
            "HTTP/1.1 200 OK",
            "X-Powered-By: PHP/8.1.2"
        );
        List<Technology> result = fingerprinter.detect("example.com",
            headers, "", List.of());
        Technology php = result.stream()
            .filter(t -> t.name.equals("PHP")).findFirst().orElse(null);
        assertNotNull(php);
        assertEquals("8.1.2", php.version);
    }

    @Test
    void detectsWordPressFromCookie() {
        List<Technology> result = fingerprinter.detect("example.com",
            List.of(), "", List.of("wordpress_logged_in_abc123"));
        assertTrue(result.stream().anyMatch(t -> t.name.equals("WordPress")));
    }

    @Test
    void vulnerableJQueryGetsCveAttached() {
        String body = "<script src='/js/jquery-1.9.0.min.js'></script>";
        List<Technology> result = fingerprinter.detect("example.com",
            List.of(), body, List.of());
        Technology jquery = result.stream()
            .filter(t -> t.name.equals("jQuery")).findFirst().orElse(null);
        assertNotNull(jquery);
        assertFalse(jquery.cves.isEmpty(), "jQuery 1.9.0 powinien mieć CVE");
    }

    @Test
    void noDuplicateTechsForSameHost() {
        String body = "<script src='/js/jquery-3.3.1.min.js'></script>" +
                      "<script src='/lib/jquery-3.3.1.min.js'></script>";
        List<Technology> result = fingerprinter.detect("example.com",
            List.of(), body, List.of());
        long count = result.stream().filter(t -> t.name.equals("jQuery")).count();
        assertEquals(1, count);
    }
}
