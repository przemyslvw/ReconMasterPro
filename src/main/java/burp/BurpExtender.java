package burp;

import burp.modules.EndpointDiscovery;
import burp.ui.EndpointsPanel;
import burp.ui.ReconMasterTab;

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
            EndpointsPanel endpointsPanel = new EndpointsPanel();

            EndpointDiscovery discovery = new EndpointDiscovery(endpointsPanel::addEndpoint);
            callbacks.registerHttpListener(discovery);

            ReconMasterTab tab = new ReconMasterTab(endpointsPanel);
            callbacks.addSuiteTab(tab);
        });

        callbacks.printOutput("ReconMaster Pro v1.0 loaded.");
    }
}
