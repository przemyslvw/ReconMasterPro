package burp.models;

import java.util.regex.Pattern;

public class SecretPattern {
    public final String name;
    public final Pattern pattern;
    public final String severity;
    public final int captureGroup;   // która grupa = wartość sekretu (0 = całe dopasowanie)

    public SecretPattern(String name, String regex, String severity, int captureGroup) {
        this.name = name;
        this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
        this.severity = severity;
        this.captureGroup = captureGroup;
    }
}
