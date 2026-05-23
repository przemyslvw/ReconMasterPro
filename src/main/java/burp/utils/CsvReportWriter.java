package burp.utils;

import burp.models.*;

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class CsvReportWriter {

    public static byte[] writeZip(ReportData data) {
        Map<String, String> files = writeCsvFiles(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            for (Map.Entry<String, String> e : files.entrySet()) {
                zos.putNextEntry(new ZipEntry(e.getKey()));
                zos.write(e.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                zos.closeEntry();
            }
        } catch (Exception ex) {
            throw new RuntimeException("CSV ZIP write failed", ex);
        }
        return baos.toByteArray();
    }

    public static Map<String, String> writeCsvFiles(ReportData data) {
        Map<String, String> files = new LinkedHashMap<>();
        files.put("endpoints.csv",    writeEndpoints(data));
        files.put("technologies.csv", writeTechnologies(data));
        files.put("secrets.csv",      writeSecrets(data));
        files.put("cors.csv",         writeCors(data));
        files.put("cloud-assets.csv", writeCloudAssets(data));
        return files;
    }

    // ── Sekcje ───────────────────────────────────────────────────────────

    private static String writeEndpoints(ReportData data) {
        StringBuilder sb = new StringBuilder(
            "host,method,path,pattern,risk_score,status_code,discovered_at\n");
        for (Endpoint e : data.endpoints) {
            sb.append(row(e.host, e.method, e.path,
                nz(e.patternGroup), str(e.riskScore),
                str(e.statusCode),
                ts(e.discoveredAt)));
        }
        return sb.toString();
    }

    private static String writeTechnologies(ReportData data) {
        StringBuilder sb = new StringBuilder(
            "name,version,category,host,highest_severity,cve_count,discovered_at\n");
        for (Technology t : data.technologies) {
            sb.append(row(t.name, nz(t.version), t.category,
                t.host, t.highestSeverity(),
                str(t.cves.size()), ts(t.discoveredAt)));
        }
        return sb.toString();
    }

    private static String writeSecrets(ReportData data) {
        StringBuilder sb = new StringBuilder(
            "severity,type,value,entropy,host,url,detected_by,discovered_at\n");
        for (Secret s : data.secrets) {
            // s.value jest już zredagowaną wersją (fullValue nie trafia)
            sb.append(row(s.severity, s.type, nz(s.value),
                str(s.entropy), s.host, nz(s.url),
                s.detectedBy, ts(s.discoveredAt)));
        }
        return sb.toString();
    }

    private static String writeCors(ReportData data) {
        StringBuilder sb = new StringBuilder(
            "severity,type,host,url,method,response_acao,probe\n");
        for (CorsFinding c : data.corsFindings) {
            sb.append(row(c.severity, c.type.name(), c.host, nz(c.url),
                c.method, nz(c.responseAcao),
                c.activeProbe ? "active" : "passive"));
        }
        return sb.toString();
    }

    private static String writeCloudAssets(ReportData data) {
        StringBuilder sb = new StringBuilder(
            "provider,bucket_or_account,access,source_type,source_url,asset_url\n");
        for (CloudAsset a : data.cloudAssets) {
            sb.append(row(a.provider.displayName, a.bucketOrAccount,
                a.accessStatus, a.sourceType,
                nz(a.sourceUrl), nz(a.url)));
        }
        return sb.toString();
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static String row(String... fields) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(csvField(fields[i]));
        }
        sb.append('\n');
        return sb.toString();
    }

    private static String csvField(String s) {
        if (s == null) return "";
        // escaping: cudzysłów → "", pole w cudzysłowy jeśli zawiera , " lub newline
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private static String str(int n)    { return String.valueOf(n); }
    private static String str(double d) { return String.format("%.4f", d); }
    private static String nz(String s)  { return s != null ? s : ""; }
    private static String ts(java.time.Instant i) {
        return i != null ? i.toString() : "";
    }
}
