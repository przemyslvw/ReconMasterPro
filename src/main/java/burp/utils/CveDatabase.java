package burp.utils;

import burp.BurpExtender;
import burp.models.CveEntry;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class CveDatabase {

    private List<CveEntry> entries = new ArrayList<>();

    public void load() {
        try (InputStream is = getClass().getResourceAsStream("/cve-database.json")) {
            if (is == null) {
                log("cve-database.json not found in classpath");
                return;
            }
            Type listType = new TypeToken<List<CveEntry>>() {}.getType();
            entries = new Gson().fromJson(new InputStreamReader(is), listType);
            log("CVE database loaded: " + entries.size() + " entries");
        } catch (Exception e) {
            log("Failed to load CVE database: " + e.getMessage());
        }
    }

    public List<CveEntry> query(String techName, String detectedVersion) {
        return entries.stream()
            .filter(e -> e.technology.equalsIgnoreCase(techName))
            .filter(e -> VersionComparator.isVulnerable(detectedVersion, e.affected_before))
            .collect(Collectors.toList());
    }

    private void log(String msg) {
        try {
            BurpExtender.callbacks.printOutput("[CVE-DB] " + msg);
        } catch (Exception ignored) {
            // w testach jednostkowych BurpExtender.callbacks = null
            System.out.println("[CVE-DB] " + msg);
        }
    }
}
