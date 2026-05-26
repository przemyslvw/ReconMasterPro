package burp.models;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class TechSignature {
    public String name;
    public String category;
    public List<String> headerPatterns;
    public List<String> bodyPatterns;
    public List<String> cookiePatterns;

    public transient List<Pattern> compiledHeaderPatterns;
    public transient List<Pattern> compiledBodyPatterns;
    public transient List<Pattern> compiledCookiePatterns;

    public void compilePatterns() {
        compiledHeaderPatterns = compile(headerPatterns);
        compiledBodyPatterns   = compile(bodyPatterns);
        compiledCookiePatterns = compile(cookiePatterns);
    }

    private static List<Pattern> compile(List<String> raw) {
        if (raw == null || raw.isEmpty()) return Collections.emptyList();
        List<Pattern> out = new ArrayList<>(raw.size());
        for (String p : raw) {
            try {
                out.add(Pattern.compile(p, Pattern.CASE_INSENSITIVE));
            } catch (PatternSyntaxException e) {
                out.add(Pattern.compile(Pattern.quote(p), Pattern.CASE_INSENSITIVE));
            }
        }
        return out;
    }
}
