package burp;

import burp.modules.CorsHunter;
import burp.modules.EndpointDiscovery;
import burp.modules.SecretsScanner;
import burp.modules.TechStackFingerprinter;
import burp.modules.TimelineAnalyzer;
import burp.ui.CorsPanel;
import burp.ui.EndpointsPanel;
import burp.ui.ReconMasterTab;
import burp.ui.SecretsPanel;
import burp.ui.TechStackPanel;
import burp.ui.TimelinePanel;
import burp.ui.GraphQLPanel;
import burp.ui.CloudAssetsPanel;
import burp.modules.GraphQLExtractor;
import burp.modules.CloudAssetsAggregator;
import burp.utils.CveDatabase;
import burp.utils.DatabaseManager;
import burp.ui.ReportPanel;
import burp.modules.ReportGenerator;
import burp.utils.SettingsManager;
import burp.ui.SettingsPanel;

import javax.swing.*;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    private DatabaseManager db;
    private CorsHunter corsHunter;
    private GraphQLExtractor graphqlExtractor;
    private CloudAssetsAggregator cloudAggregator;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("ReconMaster Pro");
        callbacks.registerExtensionStateListener(this);

        SwingUtilities.invokeLater(() -> {
            // --- Etap 10: Settings ---
            SettingsManager settings = new SettingsManager(callbacks);

            // --- Etap 5: Database ---
            db = DatabaseManager.forProduction();
            try { db.initialize(); }
            catch (Exception e) {
                callbacks.printError("DB init failed: " + e.getMessage());
                return;
            }

            // --- Etap 2 ---
            EndpointsPanel endpointsPanel = new EndpointsPanel();

            // --- Etap 3 ---
            CveDatabase cveDb = new CveDatabase();
            cveDb.load();
            TechStackPanel techPanel = new TechStackPanel();

            // --- Etap 4 ---
            SecretsPanel secretsPanel = new SecretsPanel();

            // --- Etap 5: Timeline ---
            TimelinePanel timelinePanel = new TimelinePanel();
            timelinePanel.setDatabase(db);
            TimelineAnalyzer analyzer = new TimelineAnalyzer(db, timelinePanel::addEvent);
            analyzer.setWindowMinutes(settings.getTimelineWindowMinutes());

            // --- Etap 6: CORS Hunter ---
            CorsPanel corsPanel = new CorsPanel();
            corsHunter = new CorsHunter(corsPanel::addFinding);
            corsPanel.setHunter(corsHunter);
            callbacks.registerHttpListener(corsHunter);

            // --- Etap 7: GraphQL Extractor ---
            GraphQLPanel graphqlPanel = new GraphQLPanel();
            graphqlExtractor = new GraphQLExtractor(
                graphqlPanel::addEndpoint,
                graphqlPanel::updateSchema
            );
            graphqlPanel.setExtractor(graphqlExtractor);
            callbacks.registerHttpListener(graphqlExtractor);

            // Etap 2: EndpointDiscovery z Timeline
            EndpointDiscovery discovery = new EndpointDiscovery(ep -> {
                endpointsPanel.addEndpoint(ep);
                analyzer.trackEndpoint(ep);
            });
            callbacks.registerHttpListener(discovery);

            // Etap 3: TechStackFingerprinter z Timeline
            TechStackFingerprinter fingerprinter =
                new TechStackFingerprinter(tech -> {
                    techPanel.addTechnology(tech);
                    analyzer.trackTechnology(tech);
                }, cveDb);
            fingerprinter.loadSignatures();
            callbacks.registerHttpListener(fingerprinter);

            // Etap 4: SecretsScanner z Timeline
            SecretsScanner secretsScanner = new SecretsScanner(secret -> {
                secretsPanel.addSecret(secret);
                analyzer.trackSecret(secret);
            });
            secretsScanner.setEntropyThreshold(settings.getEntropyThreshold());
            callbacks.registerHttpListener(secretsScanner);

            // --- Etap 8: Cloud Assets Aggregator ---
            CloudAssetsPanel cloudAssetsPanel = new CloudAssetsPanel();
            cloudAggregator = new CloudAssetsAggregator(cloudAssetsPanel::addAsset);
            cloudAssetsPanel.setAggregator(cloudAggregator);
            callbacks.registerHttpListener(cloudAggregator);

            // --- Etap 9: Report Generator ---
            ReportGenerator reportGenerator = new ReportGenerator(
                endpointsPanel::getEndpoints,
                techPanel::getTechnologies,
                secretsPanel::getSecrets,
                corsPanel::getFindings,
                cloudAssetsPanel::getAssets,
                graphqlPanel::getEndpoints
            );
            ReportPanel reportPanel = new ReportPanel(reportGenerator);

            SettingsPanel settingsPanel = new SettingsPanel(settings, () -> {
                secretsScanner.setEntropyThreshold(settings.getEntropyThreshold());
                analyzer.setWindowMinutes(settings.getTimelineWindowMinutes());
            });

            // --- Tab UI ---
            ReconMasterTab tab = new ReconMasterTab(endpointsPanel, techPanel, secretsPanel, timelinePanel, corsPanel, graphqlPanel, cloudAssetsPanel, reportPanel, settingsPanel);
            callbacks.addSuiteTab(tab);
        });

        callbacks.printOutput("ReconMaster Pro loaded. DB: " +
            System.getProperty("user.home") + "/.reconmaster/reconmaster.db");
    }

    @Override
    public void extensionUnloaded() {
        if (db != null) db.close();
        if (corsHunter != null) corsHunter.shutdown();
        if (graphqlExtractor != null) graphqlExtractor.shutdown();
        if (cloudAggregator != null) cloudAggregator.shutdown();
    }
}
