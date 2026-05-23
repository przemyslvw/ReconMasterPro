package burp.ui;

import burp.ITab;

import javax.swing.*;
import java.awt.*;

public class ReconMasterTab implements ITab {

    private final JTabbedPane tabbedPane;

    public ReconMasterTab(EndpointsPanel endpointsPanel, TechStackPanel techPanel,
                          SecretsPanel secretsPanel, TimelinePanel timelinePanel, CorsPanel corsPanel,
                          GraphQLPanel graphqlPanel, CloudAssetsPanel cloudAssetsPanel,
                          ReportPanel reportPanel, SettingsPanel settingsPanel) {
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Endpoints", endpointsPanel);
        tabbedPane.addTab("Technologies", techPanel);
        tabbedPane.addTab("Secrets", secretsPanel);
        tabbedPane.addTab("CORS", corsPanel);
        tabbedPane.addTab("Timeline", timelinePanel);
        tabbedPane.addTab("GraphQL", graphqlPanel);
        tabbedPane.addTab("Cloud Assets", cloudAssetsPanel);
        tabbedPane.addTab("Report", reportPanel);
        tabbedPane.addTab("Settings", settingsPanel);
    }

    @Override
    public String getTabCaption() {
        return "ReconMaster";
    }

    @Override
    public Component getUiComponent() {
        return tabbedPane;
    }
}
