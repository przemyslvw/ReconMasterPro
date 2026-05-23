package burp.utils;

import burp.models.Endpoint;
import java.util.List;

public class RiskScorer {

    private static final List<String> HIGH_RISK_KEYWORDS =
        List.of("admin", "config", "secret", "backup", "debug", "internal",
                "manage", "console", "dashboard", "actuator");

    private static final List<String> MEDIUM_RISK_KEYWORDS =
        List.of("api", "graphql", "upload", "export", "import", "token",
                "auth", "login", "password", "user", "account");

    private static final List<String> LOW_RISK_EXTENSIONS =
        List.of(".css", ".js", ".png", ".jpg", ".gif", ".svg",
                ".ico", ".woff", ".woff2", ".ttf", ".map");

    public int score(Endpoint endpoint) {
        String path = endpoint.path.toLowerCase();
        int score = 10;

        for (String ext : LOW_RISK_EXTENSIONS) {
            if (path.endsWith(ext)) return 5;
        }

        for (String kw : HIGH_RISK_KEYWORDS) {
            if (path.contains(kw)) score += 50;
        }
        for (String kw : MEDIUM_RISK_KEYWORDS) {
            if (path.contains(kw)) score += 15;
        }

        switch (endpoint.method.toUpperCase()) {
            case "DELETE": score += 25; break;
            case "PUT":    score += 20; break;
            case "PATCH":  score += 15; break;
            case "POST":   score += 10; break;
        }

        return Math.min(score, 100);
    }
}
