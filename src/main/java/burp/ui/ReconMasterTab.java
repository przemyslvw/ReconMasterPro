package burp.ui;

import burp.ITab;

import javax.swing.*;
import java.awt.*;

public class ReconMasterTab implements ITab {

    private final JPanel mainPanel;

    public ReconMasterTab() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(new JLabel("ReconMaster Pro — loading..."), BorderLayout.CENTER);
    }

    @Override
    public String getTabCaption() {
        return "ReconMaster";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
