package burp.utils;

import burp.models.*;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class MarkdownReportWriter {

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'")
                         .withZone(ZoneOffset.UTC);

    public static String write(ReportData data) {
        StringBuilder sb = new StringBuilder();
        appendHeader(sb, data);
        appendSummary(sb, data);
        appendEndpoints(sb, data);
        appendTechnologies(sb, data);
        appendSecrets(sb, data);
        appendCors(sb, data);
        appendCloudAssets(sb, data);
        return sb.toString();
    }

    // ── Sekcje ───────────────────────────────────────────────────────────

    private static void appendHeader(StringBuilder sb, ReportData data) {
        sb.append("# ReconMaster Pro — Report\n\n");
        sb.append("**Target:** ").append(data.targetHost).append("  \n");
        sb.append("**Generated:** ").append(FMT.format(data.generatedAt)).append("\n\n");
        sb.append("---\n\n");
    }

    private static void appendSummary(StringBuilder sb, ReportData data) {
        sb.append("## Summary\n\n");
        sb.append("| Category | Count |\n");
        sb.append("|----------|-------|\n");
        sb.append("| Endpoints | ").append(data.endpoints.size()).append(" |\n");
        sb.append("| Technologies | ").append(data.technologies.size()).append(" |\n");
        sb.append("| Secrets | ").append(data.secrets.size()).append(" |\n");
        sb.append("| CORS Findings | ").append(data.corsFindings.size()).append(" |\n");
        sb.append("| Cloud Assets | ").append(data.cloudAssets.size()).append(" |\n");
        sb.append("| GraphQL Endpoints | ").append(data.graphqlEndpoints.size()).append(" |\n");
        sb.append("\n---\n\n");
    }

    private static void appendEndpoints(StringBuilder sb, ReportData data) {
        sb.append("## Endpoints\n\n");
        if (data.endpoints.isEmpty()) { sb.append("_No data_\n\n"); return; }
        sb.append("| Host | Method | Path | Pattern | Risk | Status |\n");
        sb.append("|------|--------|------|---------|------|--------|\n");
        for (Endpoint e : data.endpoints) {
            sb.append("| ").append(e(e.host))
              .append(" | ").append(e(e.method))
              .append(" | ").append(e(e.path))
              .append(" | ").append(e(e.patternGroup))
              .append(" | ").append(e.riskScore)
              .append(" | ").append(e.statusCode)
              .append(" |\n");
        }
        sb.append("\n");
    }

    private static void appendTechnologies(StringBuilder sb, ReportData data) {
        sb.append("## Technologies\n\n");
        if (data.technologies.isEmpty()) { sb.append("_No data_\n\n"); return; }
        sb.append("| Name | Version | Category | Host | Highest CVE | CVEs |\n");
        sb.append("|------|---------|----------|------|-------------|------|\n");
        for (Technology t : data.technologies) {
            sb.append("| ").append(e(t.name))
              .append(" | ").append(e(t.version))
              .append(" | ").append(e(t.category))
              .append(" | ").append(e(t.host))
              .append(" | ").append(t.highestSeverity())
              .append(" | ").append(t.cves.size())
              .append(" |\n");
        }
        sb.append("\n");
    }

    private static void appendSecrets(StringBuilder sb, ReportData data) {
        sb.append("## Secrets\n\n");
        if (data.secrets.isEmpty()) { sb.append("_No data_\n\n"); return; }
        sb.append("| Severity | Type | Value | Host | URL | Method |\n");
        sb.append("|----------|------|-------|------|-----|--------|\n");
        for (Secret s : data.secrets) {
            sb.append("| ").append(e(s.severity))
              .append(" | ").append(e(s.type))
              .append(" | `").append(e(s.value)).append("`")
              .append(" | ").append(e(s.host))
              .append(" | ").append(e(s.url))
              .append(" | ").append(e(s.detectedBy))
              .append(" |\n");
        }
        sb.append("\n");
    }

    private static void appendCors(StringBuilder sb, ReportData data) {
        sb.append("## CORS Findings\n\n");
        if (data.corsFindings.isEmpty()) { sb.append("_No data_\n\n"); return; }
        sb.append("| Severity | Type | Host | URL | Method | ACAO | Probe |\n");
        sb.append("|----------|------|------|-----|--------|------|-------|\n");
        for (CorsFinding c : data.corsFindings) {
            sb.append("| ").append(e(c.severity))
              .append(" | ").append(c.type.name())
              .append(" | ").append(e(c.host))
              .append(" | ").append(e(c.url))
              .append(" | ").append(e(c.method))
              .append(" | ").append(e(c.responseAcao))
              .append(" | ").append(c.activeProbe ? "active" : "passive")
              .append(" |\n");
        }
        sb.append("\n");
    }

    private static void appendCloudAssets(StringBuilder sb, ReportData data) {
        sb.append("## Cloud Assets\n\n");
        if (data.cloudAssets.isEmpty()) { sb.append("_No data_\n\n"); return; }
        sb.append("| Provider | Bucket/Account | Access | Source | Asset URL |\n");
        sb.append("|----------|----------------|--------|--------|-----------|\n");
        for (CloudAsset a : data.cloudAssets) {
            sb.append("| ").append(e(a.provider.displayName))
              .append(" | ").append(e(a.bucketOrAccount))
              .append(" | ").append(e(a.accessStatus))
              .append(" | ").append(e(a.sourceType))
              .append(" | ").append(e(a.url))
              .append(" |\n");
        }
        sb.append("\n");
    }

    // escape pipe characters w komórkach Markdown
    private static String e(String s) {
        if (s == null) return "";
        return s.replace("|", "\\|");
    }
}
