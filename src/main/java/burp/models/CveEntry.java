package burp.models;

public class CveEntry {
    public String cve_id;
    public String technology;
    public String severity;
    public double cvss;
    public String affected_before;   // null = wszystkie wersje
    public String description;
}
