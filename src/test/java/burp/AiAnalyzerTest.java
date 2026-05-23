package burp;

import burp.models.*;
import burp.modules.AiAnalyzer;
import burp.utils.SettingsManager;
import burp.utils.AiProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class AiAnalyzerTest {

    private Map<String, String> configStore;
    private IBurpExtenderCallbacks fakeCallbacks;
    private SettingsManager settings;

    // Suppliers lists
    private List<Endpoint> endpoints;
    private List<Technology> technologies;
    private List<Secret> secrets;
    private List<CorsFinding> corsFindings;
    private List<CloudAsset> cloudAssets;
    private List<GraphQLEndpoint> graphqlEndpoints;

    private AiAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        configStore = new HashMap<>();
        fakeCallbacks = (IBurpExtenderCallbacks) Proxy.newProxyInstance(
            IBurpExtenderCallbacks.class.getClassLoader(),
            new Class<?>[]{IBurpExtenderCallbacks.class},
            (proxy, method, args) -> {
                if ("saveExtensionSetting".equals(method.getName())) {
                    configStore.put((String) args[0], (String) args[1]);
                    return null;
                } else if ("loadExtensionSetting".equals(method.getName())) {
                    return configStore.get((String) args[0]);
                }
                return null;
            }
        );
        settings = new SettingsManager(fakeCallbacks);

        endpoints = new ArrayList<>();
        technologies = new ArrayList<>();
        secrets = new ArrayList<>();
        corsFindings = new ArrayList<>();
        cloudAssets = new ArrayList<>();
        graphqlEndpoints = new ArrayList<>();

        analyzer = new AiAnalyzer(
            settings,
            () -> endpoints,
            () -> technologies,
            () -> secrets,
            () -> corsFindings,
            () -> cloudAssets,
            () -> graphqlEndpoints
        );
    }

    @Test
    void systemPromptIncludesCoreHeadings() {
        String prompt = analyzer.buildSystemPrompt();
        assertNotNull(prompt);
        assertTrue(prompt.contains("Podsumowanie ryzyka"));
        assertTrue(prompt.contains("Rekomendowane ataki"));
        assertTrue(prompt.contains("Przykładowe polecenia / POC"));
    }

    @Test
    void interestingEndpointsSortedAndLimited() {
        for (int i = 1; i <= 105; i++) {
            Endpoint ep = new Endpoint("example.com", "GET", "/path" + i, 200);
            ep.riskScore = i;
            endpoints.add(ep);
        }

        String report = analyzer.buildUserPrompt();
        assertNotNull(report);

        // Since we sort by riskScore descending, top 100 should be included.
        // /path105 should be there. /path1 should be excluded.
        assertTrue(report.contains("/path105"));
        assertFalse(report.contains("/path1 |"));
    }

    @Test
    void domainMaskingOpSecConvertsHosts() {
        settings.setAiMaskDomains(true);

        endpoints.add(new Endpoint("target.com", "GET", "/api", 200));
        endpoints.add(new Endpoint("api.target.com", "POST", "/login", 200));
        endpoints.add(new Endpoint("192.168.1.100", "GET", "/status", 200));

        Map<String, String> hostMap = analyzer.buildOpSecHostMap();

        assertEquals("10.0.0.1", hostMap.get("192.168.1.100"));
        assertTrue(hostMap.get("target.com").startsWith("target-"));
        assertTrue(hostMap.get("api.target.com").startsWith("target-"));
        assertNotEquals(hostMap.get("target.com"), hostMap.get("api.target.com"));

        String text = "Contact api.target.com or target.com or 192.168.1.100";
        String masked = analyzer.maskText(text, hostMap);

        assertFalse(masked.contains("target.com"));
        assertFalse(masked.contains("192.168.1.100"));
        assertTrue(masked.contains(hostMap.get("api.target.com")));
        assertTrue(masked.contains(hostMap.get("target.com")));
        assertTrue(masked.contains("10.0.0.1"));
    }

    @Test
    void secretRedactionBasedOnSettings() {
        Secret sec = new Secret("Slack Webhook", "HIGH", "xoxb-123456789-abcdef", "token context", "target.com", "/url", "regex");
        secrets.add(sec);

        settings.setAiMaskSecrets(true);
        String reportWithMask = analyzer.buildUserPrompt();
        assertTrue(reportWithMask.contains("xoxb-123...cdef"));
        assertFalse(reportWithMask.contains("xoxb-123456789-abcdef"));

        settings.setAiMaskSecrets(false);
        String reportNoMask = analyzer.buildUserPrompt();
        assertTrue(reportNoMask.contains("xoxb-123456789-abcdef"));
    }

    @Test
    void aggregatesAllPanelTypes() {
        settings.setAiMaskDomains(false);

        Technology tech = new Technology("Apache", "Web Server", "myhost.com");
        CveEntry cve = new CveEntry();
        cve.cve_id = "CVE-2024-1234";
        cve.cvss = 9.8;
        cve.severity = "CRITICAL";
        cve.description = "RCE in apache";
        tech.cves.add(cve);
        technologies.add(tech);

        corsFindings.add(new CorsFinding(CorsFinding.IssueType.REFLECTED_ORIGIN_CREDENTIALS, "myhost.com", "http://myhost.com/cors", "GET"));

        GraphQLEndpoint gql = new GraphQLEndpoint("myhost.com", "http://myhost.com/graphql", "path");
        gql.introspectionEnabled = true;
        graphqlEndpoints.add(gql);

        cloudAssets.add(new CloudAsset(CloudProvider.S3, "my-bucket", "http://s3.amazonaws.com/my-bucket", "http://myhost.com", "body"));

        String report = analyzer.buildUserPrompt();

        assertTrue(report.contains("Apache"));
        assertTrue(report.contains("CVE-2024-1234"));
        assertTrue(report.contains("REFLECTED_ORIGIN_CREDENTIALS"));
        assertTrue(report.contains("Introspection Enabled"));
        assertTrue(report.contains("my-bucket"));
    }
}
