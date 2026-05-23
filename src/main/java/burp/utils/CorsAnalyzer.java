package burp.utils;

import burp.models.CorsFinding;

import java.util.Map;
import java.util.Optional;

public class CorsAnalyzer {

    public static Optional<CorsFinding> analyze(String host, String url, String method,
                                                 Map<String, String> responseHeaders,
                                                 String testedOrigin) {
        String acao = getHeader(responseHeaders, "access-control-allow-origin");
        if (acao == null) return Optional.empty();

        String acac = getHeader(responseHeaders, "access-control-allow-credentials");
        boolean hasCredentials = "true".equalsIgnoreCase(acac);

        CorsFinding.IssueType type = classify(acao, hasCredentials, testedOrigin, host);
        if (type == null) return Optional.empty();

        CorsFinding finding = new CorsFinding(type, host, url, method);
        finding.testedOrigin = testedOrigin;
        finding.responseAcao = acao;
        finding.responseAcac = acac;
        finding.activeProbe = testedOrigin != null;
        return Optional.of(finding);
    }

    private static CorsFinding.IssueType classify(String acao, boolean hasCredentials,
                                                   String testedOrigin, String host) {
        if (testedOrigin != null && acao.equalsIgnoreCase(testedOrigin)) {
            return hasCredentials
                ? CorsFinding.IssueType.REFLECTED_ORIGIN_CREDENTIALS
                : CorsFinding.IssueType.REFLECTED_ORIGIN;
        }

        if ("null".equalsIgnoreCase(acao)) {
            return hasCredentials
                ? CorsFinding.IssueType.NULL_ORIGIN_CREDENTIALS
                : CorsFinding.IssueType.NULL_ORIGIN;
        }

        if ("*".equals(acao)) {
            return hasCredentials
                ? CorsFinding.IssueType.CREDENTIALED_WILDCARD
                : CorsFinding.IssueType.WILDCARD_ORIGIN;
        }

        return null;
    }

    private static String getHeader(Map<String, String> headers, String nameLower) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().toLowerCase().equals(nameLower)) {
                return entry.getValue();
            }
        }
        return null;
    }
}
