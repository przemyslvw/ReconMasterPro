package burp.ui;

import burp.ITab;

import javax.swing.*;
import java.awt.*;

public class ReconMasterTab implements ITab {

    private final JTabbedPane tabbedPane;

    public ReconMasterTab(EndpointsPanel endpointsPanel, TechStackPanel techPanel) {
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Endpoints", endpointsPanel);
        tabbedPane.addTab("Technologies", techPanel);
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
