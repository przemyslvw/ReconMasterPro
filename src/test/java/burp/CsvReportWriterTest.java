package burp;

import burp.models.*;
import burp.utils.CsvReportWriter;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.junit.jupiter.api.Assertions.*;

class CsvReportWriterTest {

    private ReportData emptyReport() {
        return new ReportData("example.com",
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    void outputIsValidZip() throws Exception {
        byte[] zip = CsvReportWriter.writeZip(emptyReport());
        assertNotNull(zip);
        assertTrue(zip.length > 0);
        // weryfikacja magic bytes ZIP: PK\x03\x04
        assertEquals(0x50, zip[0] & 0xFF);
        assertEquals(0x4B, zip[1] & 0xFF);
    }

    @Test
    void zipContainsFiveFiles() throws Exception {
        byte[] zip = CsvReportWriter.writeZip(emptyReport());
        int count = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            while (zis.getNextEntry() != null) count++;
        }
        assertEquals(5, count, "ZIP musi zawierać 5 plików CSV");
    }

    @Test
    void zipContainsExpectedFileNames() throws Exception {
        byte[] zip = CsvReportWriter.writeZip(emptyReport());
        java.util.Set<String> names = new java.util.HashSet<>();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) names.add(entry.getName());
        }
        assertTrue(names.contains("endpoints.csv"));
        assertTrue(names.contains("technologies.csv"));
        assertTrue(names.contains("secrets.csv"));
        assertTrue(names.contains("cors.csv"));
        assertTrue(names.contains("cloud-assets.csv"));
    }

    @Test
    void endpointsCsvHasHeader() {
        Map<String, String> files = CsvReportWriter.writeCsvFiles(emptyReport());
        String csv = files.get("endpoints.csv");
        assertNotNull(csv);
        assertTrue(csv.startsWith("host,method,path,pattern,risk_score,status_code,discovered_at\n"),
            "endpoints.csv musi mieć nagłówek");
    }

    @Test
    void endpointsCsvContainsData() {
        Endpoint ep = new Endpoint("example.com", "POST", "/api/login", 200);
        ep.patternGroup = "/api/login";
        ep.riskScore = 80;
        ReportData data = new ReportData("example.com",
            List.of(ep), List.of(), List.of(), List.of(), List.of(), List.of());

        Map<String, String> files = CsvReportWriter.writeCsvFiles(data);
        String csv = files.get("endpoints.csv");
        assertTrue(csv.contains("example.com"));
        assertTrue(csv.contains("POST"));
        assertTrue(csv.contains("/api/login"));
        assertTrue(csv.contains("80"));
    }

    @Test
    void secretsCsvRedactsFullValue() {
        Secret s = new Secret("AWS Key", "CRITICAL",
            "AKIAIOSFODNN7EXAMPLE", "ctx", "example.com",
            "https://example.com/app.js", "regex");
        ReportData data = new ReportData("example.com",
            List.of(), List.of(), List.of(s), List.of(), List.of(), List.of());

        Map<String, String> files = CsvReportWriter.writeCsvFiles(data);
        String csv = files.get("secrets.csv");
        assertFalse(csv.contains("AKIAIOSFODNN7EXAMPLE"),
            "Pełna wartość sekretu nie może trafić do CSV");
    }

    @Test
    void corsCsvHasCorrectHeader() {
        Map<String, String> files = CsvReportWriter.writeCsvFiles(emptyReport());
        String csv = files.get("cors.csv");
        assertTrue(csv.startsWith("severity,type,host,url,method,response_acao,probe\n"));
    }

    @Test
    void csvFieldsWithCommasAreQuoted() {
        Endpoint ep = new Endpoint("example.com", "GET", "/path,with,commas", 200);
        ReportData data = new ReportData("example.com",
            List.of(ep), List.of(), List.of(), List.of(), List.of(), List.of());

        Map<String, String> files = CsvReportWriter.writeCsvFiles(data);
        String csv = files.get("endpoints.csv");
        assertTrue(csv.contains("\"/path,with,commas\""),
            "Pola CSV z przecinkami muszą być w cudzysłowach");
    }
}
