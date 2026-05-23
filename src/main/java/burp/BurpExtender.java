package burp;

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

        SwingUtilities.invokeLater(() ->
            callbacks.addSuiteTab(new ReconMasterTab())
        );

        callbacks.printOutput("ReconMaster Pro loaded.");
    }
}
