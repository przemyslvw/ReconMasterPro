package burp.utils;

import java.util.regex.Pattern;

public class PatternMatcher {

    private static final Pattern UUID_RE =
        Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern HEX_HASH_RE =
        Pattern.compile("(?<![\\w-])[0-9a-f]{32,}(?=[.?#]|$)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern NUMERIC_RE =
        Pattern.compile("(?<=/|^)\\d+(?=/|$|\\.)");

    public String normalize(String path) {
        if (path == null || path.isEmpty()) return "/";

        String[] parts = path.split("\\?", 2);
        String normalized = parts[0];

        normalized = UUID_RE.matcher(normalized).replaceAll("{uuid}");
        normalized = HEX_HASH_RE.matcher(normalized).replaceAll("{hash}");
        normalized = NUMERIC_RE.matcher(normalized).replaceAll("{id}");

        return normalized;
    }
}
