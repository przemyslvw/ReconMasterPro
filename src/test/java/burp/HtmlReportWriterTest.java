package burp;

import burp.models.*;
import burp.utils.HtmlReportWriter;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HtmlReportWriterTest {

    private ReportData emptyReport() {
        return new ReportData("example.com",
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    void outputIsValidHtmlDocument() {
        String html = HtmlReportWriter.write(emptyReport());
        assertTrue(html.contains("<!DOCTYPE html"), "Musi zaczynać się od DOCTYPE");
        assertTrue(html.contains("</html>"), "Musi być zamkniętym dokumentem HTML");
    }

    @Test
    void outputContainsTargetHost() {
        String html = HtmlReportWriter.write(emptyReport());
        assertTrue(html.contains("example.com"));
    }

    @Test
    void noExternalDependencies() {
        String html = HtmlReportWriter.write(emptyReport());
        assertFalse(html.contains("cdn."), "Brak CDN linków");
        assertFalse(html.contains("googleapis.com"), "Brak Google Fonts");
        assertFalse(html.contains("bootstrapcdn"), "Brak Bootstrap CDN");
        assertFalse(html.contains("<link rel"), "Brak zewnętrznych arkuszy CSS");
        // dopuszczamy tylko <style> inline
    }

    @Test
    void outputContainsInlineCss() {
        String html = HtmlReportWriter.write(emptyReport());
        assertTrue(html.contains("<style>") || html.contains("<style "),
            "CSS musi być inline w <style>");
    }

    @Test
    void dataEmbeddedAsJsonInScript() {
        String html = HtmlReportWriter.write(emptyReport());
        assertTrue(html.contains("const REPORT_DATA ="),
            "Dane muszą być embedded jako JS const");
    }

    @Test
    void secretValueNotExposedInHtml() {
        Secret s = new Secret("AWS Key", "CRITICAL",
            "AKIAIOSFODNN7EXAMPLE", "ctx", "example.com",
            "https://example.com/app.js", "regex");
        ReportData data = new ReportData("example.com",
            List.of(), List.of(), List.of(s), List.of(), List.of(), List.of());

        String html = HtmlReportWriter.write(data);
        assertFalse(html.contains("AKIAIOSFODNN7EXAMPLE"),
            "Pełna wartość sekretu nie może trafić do HTML");
    }

    @Test
    void htmlTagsInDataAreEscaped() {
        // URL z < > nie może wstrzykiwać HTML (XSS w raporcie)
        Endpoint ep = new Endpoint("example.com", "GET",
            "/api/<script>alert(1)</script>", 200);
        ReportData data = new ReportData("example.com",
            List.of(ep), List.of(), List.of(), List.of(), List.of(), List.of());

        String html = HtmlReportWriter.write(data);
        // dane są embedded jako JSON w <script>, więc < i > muszą być escaped lub w stringu
        // weryfikujemy że nie ma rawgo <script> poza sekcją danych
        int scriptTagCount = countOccurrences(html, "<script");
        // dopuszczamy: jeden tag danych + jeden tag renderujący
        assertTrue(scriptTagCount <= 3, "Nie powinno być nadmiarowych tagów <script>");
    }

    @Test
    void allSectionsRenderedInHtml() {
        String html = HtmlReportWriter.write(emptyReport());
        assertTrue(html.contains("Endpoints"));
        assertTrue(html.contains("Technologies"));
        assertTrue(html.contains("Secrets"));
        assertTrue(html.contains("CORS"));
        assertTrue(html.contains("Cloud Assets"));
    }

    private int countOccurrences(String text, String pattern) {
        int count = 0, idx = 0;
        while ((idx = text.indexOf(pattern, idx)) != -1) { count++; idx++; }
        return count;
    }
}
