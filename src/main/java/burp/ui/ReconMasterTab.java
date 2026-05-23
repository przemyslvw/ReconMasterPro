package burp.ui;

import javax.swing.*;

public class ReconMasterTab extends JTabbedPane {

    public ReconMasterTab(EndpointsPanel endpointsPanel, TechStackPanel techPanel,
                          SecretsPanel secretsPanel, TimelinePanel timelinePanel, CorsPanel corsPanel,
                          GraphQLPanel graphqlPanel, CloudAssetsPanel cloudAssetsPanel,
                          ReportPanel reportPanel, AiAssistantPanel aiAssistantPanel,
                          SettingsPanel settingsPanel, AboutPanel aboutPanel) {
        addTab("Endpoints", endpointsPanel);
        addTab("Technologies", techPanel);
        addTab("Secrets", secretsPanel);
        addTab("CORS", corsPanel);
        addTab("Timeline", timelinePanel);
        addTab("GraphQL", graphqlPanel);
        addTab("Cloud Assets", cloudAssetsPanel);
        addTab("Report", reportPanel);
        addTab("AI Assistant", aiAssistantPanel);
        addTab("Settings", settingsPanel);
        addTab("About", aboutPanel);
    }
}
