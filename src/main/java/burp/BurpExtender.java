package burp;

import burp.modules.EndpointDiscovery;
import burp.modules.SecretsScanner;
import burp.modules.TechStackFingerprinter;
import burp.ui.EndpointsPanel;
import burp.ui.ReconMasterTab;
import burp.ui.SecretsPanel;
import burp.ui.TechStackPanel;
import burp.utils.CveDatabase;

import javax.swing.*;

public class BurpExtender implements IBurpExtender {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("ReconMaster Pro");

        SwingUtilities.invokeLater(() -> {
            // --- Etap 2 ---
            EndpointsPanel endpointsPanel = new EndpointsPanel();
            EndpointDiscovery discovery = new EndpointDiscovery(endpointsPanel::addEndpoint);
            callbacks.registerHttpListener(discovery);

            // --- Etap 3 ---
            CveDatabase cveDb = new CveDatabase();
            cveDb.load();

            TechStackPanel techPanel = new TechStackPanel();
            TechStackFingerprinter fingerprinter =
                new TechStackFingerprinter(techPanel::addTechnology, cveDb);
            fingerprinter.loadSignatures();
            callbacks.registerHttpListener(fingerprinter);

            // --- Etap 4 ---
            SecretsPanel secretsPanel = new SecretsPanel();
            SecretsScanner secretsScanner = new SecretsScanner(secretsPanel::addSecret);
            callbacks.registerHttpListener(secretsScanner);

            // --- Tab UI ---
            ReconMasterTab tab = new ReconMasterTab(endpointsPanel, techPanel, secretsPanel);
            callbacks.addSuiteTab(tab);
        });

        callbacks.printOutput("ReconMaster Pro v1.0 loaded.");
    }
}
