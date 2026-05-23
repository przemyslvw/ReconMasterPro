package burp;

import burp.models.*;
import burp.utils.MarkdownReportWriter;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MarkdownReportWriterTest {

    private ReportData emptyReport() {
        return new ReportData("example.com",
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    void outputStartsWithH1Title() {
        String md = MarkdownReportWriter.write(emptyReport());
        assertTrue(md.startsWith("# ReconMaster Pro — Report"),
            "Raport musi zaczynać się od nagłówka H1");
    }

    @Test
    void outputContainsTargetAndDate() {
        String md = MarkdownReportWriter.write(emptyReport());
        assertTrue(md.contains("example.com"), "Raport musi zawierać target host");
        assertTrue(md.contains("Generated"), "Raport musi zawierać datę generacji");
    }

    @Test
    void outputContainsSummarySection() {
        String md = MarkdownReportWriter.write(emptyReport());
        assertTrue(md.contains("## Summary"), "Raport musi mieć sekcję Summary");
    }

    @Test
    void allSectionsPresent() {
        String md = MarkdownReportWriter.write(emptyReport());
        assertTrue(md.contains("## Endpoints"));
        assertTrue(md.contains("## Technologies"));
        assertTrue(md.contains("## Secrets"));
        assertTrue(md.contains("## CORS Findings"));
        assertTrue(md.contains("## Cloud Assets"));
    }

    @Test
    void emptySectionShowsNoDataMessage() {
        String md = MarkdownReportWriter.write(emptyReport());
        assertTrue(md.contains("_No data_"),
            "Pusta sekcja musi wyświetlać '_No data_'");
    }

    @Test
    void endpointTableHasCorrectColumns() {
        Endpoint ep = new Endpoint("example.com", "GET", "/api/users", 200);
        ReportData data = new ReportData("example.com",
            List.of(ep), List.of(), List.of(), List.of(), List.of(), List.of());

        String md = MarkdownReportWriter.write(data);
        assertTrue(md.contains("| Method |"), "Tabela endpoints musi mieć kolumnę Method");
        assertTrue(md.contains("| Path |"),   "Tabela endpoints musi mieć kolumnę Path");
        assertTrue(md.contains("| Risk |"),   "Tabela endpoints musi mieć kolumnę Risk");
    }

    @Test
    void secretValueRedactedInMarkdown() {
        Secret s = new Secret("AWS Key", "CRITICAL",
            "AKIAIOSFODNN7EXAMPLE", "ctx", "example.com",
            "https://example.com/app.js", "regex");
        ReportData data = new ReportData("example.com",
            List.of(), List.of(), List.of(s), List.of(), List.of(), List.of());

        String md = MarkdownReportWriter.write(data);
        assertFalse(md.contains("AKIAIOSFODNN7EXAMPLE"),
            "Pełna wartość sekretu nie może trafić do Markdown");
    }

    @Test
    void corsTableHasSeverityColumn() {
        CorsFinding f = new CorsFinding(
            CorsFinding.IssueType.WILDCARD_ORIGIN, "example.com",
            "https://example.com/api", "GET");
        f.responseAcao = "*";
        ReportData data = new ReportData("example.com",
            List.of(), List.of(), List.of(), List.of(f), List.of(), List.of());

        String md = MarkdownReportWriter.write(data);
        assertTrue(md.contains("| Severity |"));
        assertTrue(md.contains("LOW"));
    }

    @Test
    void summaryCountsAreCorrect() {
        Endpoint ep = new Endpoint("example.com", "GET", "/api", 200);
        Secret s = new Secret("GitHub Token", "HIGH", "ghp_abc123XYZ",
            "ctx", "example.com", "https://example.com/app.js", "regex");
        ReportData data = new ReportData("example.com",
            List.of(ep), List.of(), List.of(s), List.of(), List.of(), List.of());

        String md = MarkdownReportWriter.write(data);
        assertTrue(md.contains("1") && md.contains("Endpoints"),
            "Summary musi pokazywać liczbę endpointów");
    }
}
