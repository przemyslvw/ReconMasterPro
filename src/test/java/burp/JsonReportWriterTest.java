package burp;

import burp.models.*;
import burp.utils.JsonReportWriter;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JsonReportWriterTest {

    private ReportData emptyReport() {
        return new ReportData("example.com",
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    void outputIsValidJsonObject() {
        String json = JsonReportWriter.write(emptyReport());
        assertTrue(json.startsWith("{"), "JSON musi zaczynać się od {");
        assertTrue(json.endsWith("}"), "JSON musi kończyć się na }");
    }

    @Test
    void outputContainsTargetHost() {
        String json = JsonReportWriter.write(emptyReport());
        assertTrue(json.contains("\"targetHost\""), "JSON musi zawierać targetHost");
        assertTrue(json.contains("example.com"));
    }

    @Test
    void outputContainsGeneratedAt() {
        String json = JsonReportWriter.write(emptyReport());
        assertTrue(json.contains("\"generatedAt\""), "JSON musi zawierać generatedAt");
    }

    @Test
    void outputContainsAllSections() {
        String json = JsonReportWriter.write(emptyReport());
        assertTrue(json.contains("\"endpoints\""));
        assertTrue(json.contains("\"technologies\""));
        assertTrue(json.contains("\"secrets\""));
        assertTrue(json.contains("\"corsFindings\""));
        assertTrue(json.contains("\"cloudAssets\""));
        assertTrue(json.contains("\"graphqlEndpoints\""));
    }

    @Test
    void endpointDataSerializedCorrectly() {
        Endpoint ep = new Endpoint("example.com", "GET", "/api/users", 200);
        ep.riskScore = 42;
        ReportData data = new ReportData("example.com",
            List.of(ep), List.of(), List.of(), List.of(), List.of(), List.of());

        String json = JsonReportWriter.write(data);
        assertTrue(json.contains("\"/api/users\""));
        assertTrue(json.contains("\"GET\""));
        assertTrue(json.contains("42"));
    }

    @Test
    void secretValueRedactedInOutput() {
        Secret s = new Secret("AWS Key", "CRITICAL",
            "AKIAIOSFODNN7EXAMPLE", "context", "example.com",
            "https://example.com/app.js", "regex");
        ReportData data = new ReportData("example.com",
            List.of(), List.of(), List.of(s), List.of(), List.of(), List.of());

        String json = JsonReportWriter.write(data);
        // fullValue nie powinien trafić do raportu (pole `value` = zredagowane)
        assertFalse(json.contains("AKIAIOSFODNN7EXAMPLE"),
            "Pełna wartość sekretu nie może trafić do raportu JSON");
        assertTrue(json.contains("AKIAIOSS"), "Zredagowany prefix musi być w raporcie");
    }

    @Test
    void instantSerializedAsIsoString() {
        String json = JsonReportWriter.write(emptyReport());
        // Instant musi być ISO-8601, nie timestamp w milisekundach
        assertTrue(json.matches("[\\s\\S]*\"generatedAt\"\\s*:\\s*\"\\d{4}-\\d{2}-\\d{2}T[\\s\\S]*"),
            "generatedAt musi być w formacie ISO-8601");
    }

    @Test
    void emptyListsSerializedAsArrays() {
        String json = JsonReportWriter.write(emptyReport());
        assertTrue(json.contains("\"endpoints\": []") || json.contains("\"endpoints\":[]"),
            "Puste listy muszą być tablicami JSON, nie null");
    }
}
