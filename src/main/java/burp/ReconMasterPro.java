package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.modules.*;
import burp.ui.*;
import burp.utils.CveDatabase;
import burp.utils.DatabaseManager;
import burp.utils.SettingsManager;

import javax.swing.*;

public class ReconMasterPro implements BurpExtension {

    public static MontoyaApi api;
    private DatabaseManager db;
    private CorsHunter corsHunter;
    private GraphQLExtractor graphqlExtractor;
    private CloudAssetsAggregator cloudAggregator;

    @Override
    public void initialize(MontoyaApi api) {
        ReconMasterPro.api = api;
        api.extension().setName("ReconMaster Pro");

        SwingUtilities.invokeLater(() -> {
            SettingsManager settings = new SettingsManager(api);

            db = DatabaseManager.forProduction();
            try {
                db.initialize();
            } catch (Exception e) {
                api.logging().raiseErrorEvent("DB init failed: " + e.getMessage());
                return;
            }

            EndpointsPanel endpointsPanel = new EndpointsPanel(api);

            CveDatabase cveDb = new CveDatabase();
            cveDb.load();
            TechStackPanel techPanel = new TechStackPanel(api);

            SecretsPanel secretsPanel = new SecretsPanel(api);

            TimelinePanel timelinePanel = new TimelinePanel(api);
            timelinePanel.setDatabase(db);
            TimelineAnalyzer analyzer = new TimelineAnalyzer(db, timelinePanel::addEvent);
            analyzer.setWindowMinutes(settings.getTimelineWindowMinutes());

            CorsPanel corsPanel = new CorsPanel(api);
            corsHunter = new CorsHunter(corsPanel::addFinding);
            corsPanel.setHunter(corsHunter);
            api.http().registerHttpHandler(corsHunter);

            GraphQLPanel graphqlPanel = new GraphQLPanel(api);
            graphqlExtractor = new GraphQLExtractor(
                graphqlPanel::addEndpoint,
                graphqlPanel::updateSchema
            );
            graphqlPanel.setExtractor(graphqlExtractor);
            api.http().registerHttpHandler(graphqlExtractor);

            EndpointDiscovery discovery = new EndpointDiscovery(ep -> {
                endpointsPanel.addEndpoint(ep);
                analyzer.trackEndpoint(ep);
            });
            api.http().registerHttpHandler(discovery);

            TechStackFingerprinter fingerprinter = new TechStackFingerprinter(tech -> {
                techPanel.addTechnology(tech);
                analyzer.trackTechnology(tech);
            }, cveDb);
            fingerprinter.loadSignatures();
            api.http().registerHttpHandler(fingerprinter);

            SecretsScanner secretsScanner = new SecretsScanner(secret -> {
                secretsPanel.addSecret(secret);
                analyzer.trackSecret(secret);
            });
            secretsScanner.setEntropyThreshold(settings.getEntropyThreshold());
            api.http().registerHttpHandler(secretsScanner);

            CloudAssetsPanel cloudAssetsPanel = new CloudAssetsPanel(api);
            cloudAggregator = new CloudAssetsAggregator(cloudAssetsPanel::addAsset);
            cloudAssetsPanel.setAggregator(cloudAggregator);
            api.http().registerHttpHandler(cloudAggregator);

            ReportGenerator reportGenerator = new ReportGenerator(
                endpointsPanel::getEndpoints,
                techPanel::getTechnologies,
                secretsPanel::getSecrets,
                corsPanel::getFindings,
                cloudAssetsPanel::getAssets,
                graphqlPanel::getEndpoints
            );
            ReportPanel reportPanel = new ReportPanel(reportGenerator);

            AiAssistantPanel aiAssistantPanel = new AiAssistantPanel(
                settings,
                endpointsPanel::getEndpoints,
                techPanel::getTechnologies,
                secretsPanel::getSecrets,
                corsPanel::getFindings,
                cloudAssetsPanel::getAssets,
                graphqlPanel::getEndpoints
            );

            SettingsPanel settingsPanel = new SettingsPanel(settings, () -> {
                secretsScanner.setEntropyThreshold(settings.getEntropyThreshold());
                analyzer.setWindowMinutes(settings.getTimelineWindowMinutes());
                aiAssistantPanel.refreshSettings();
            });

            ReconMasterTab tab = new ReconMasterTab(
                endpointsPanel, techPanel, secretsPanel, timelinePanel, corsPanel,
                graphqlPanel, cloudAssetsPanel, reportPanel, aiAssistantPanel, settingsPanel
            );

            api.userInterface().registerSuiteTab("ReconMaster Pro", tab);
        });

        api.extension().registerUnloadingHandler(() -> {
            try {
                if (db != null) db.close();
                if (corsHunter != null) corsHunter.shutdown();
                if (graphqlExtractor != null) graphqlExtractor.shutdown();
                if (cloudAggregator != null) cloudAggregator.shutdown();
            } catch (Exception ignored) {}
        });

        api.logging().logToOutput("ReconMaster Pro loaded (Montoya API Edition). DB: " +
            System.getProperty("user.home") + "/.reconmaster/reconmaster.db");
    }
}
