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
import burp.utils.CveDatabase;
import burp.utils.DatabaseManager;

import javax.swing.*;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    private DatabaseManager db;
    private CorsHunter corsHunter;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("ReconMaster Pro");
        callbacks.registerExtensionStateListener(this);

        SwingUtilities.invokeLater(() -> {
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

            // --- Etap 6: CORS Hunter ---
            CorsPanel corsPanel = new CorsPanel();
            corsHunter = new CorsHunter(corsPanel::addFinding);
            corsPanel.setHunter(corsHunter);
            callbacks.registerHttpListener(corsHunter);

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
            callbacks.registerHttpListener(secretsScanner);

            // --- Tab UI ---
            ReconMasterTab tab = new ReconMasterTab(endpointsPanel, techPanel, secretsPanel, timelinePanel, corsPanel);
            callbacks.addSuiteTab(tab);
        });

        callbacks.printOutput("ReconMaster Pro loaded. DB: " +
            System.getProperty("user.home") + "/.reconmaster/reconmaster.db");
    }

    @Override
    public void extensionUnloaded() {
        if (db != null) db.close();
        if (corsHunter != null) corsHunter.shutdown();
    }
}
