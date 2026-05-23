package burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.HyperlinkEvent;
import java.awt.*;
import java.io.IOException;
import java.net.URI;

public class AboutPanel extends JPanel {

    private static final Color ACCENT     = new Color(0xFF, 0x66, 0x00); // Burp orange
    private static final Color LINK_COLOR = new Color(0x1a, 0x73, 0xe8);

    public AboutPanel() {
        super(new GridBagLayout());
        setBorder(new EmptyBorder(40, 40, 40, 40));

        JPanel card = buildCard();

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill   = GridBagConstraints.NONE;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        add(card, gbc);
    }

    // ── Main card ─────────────────────────────────────────────────────────────

    private JPanel buildCard() {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0xDD, 0xDD, 0xDD), 1),
                new EmptyBorder(32, 40, 32, 40)
        ));
        card.setMaximumSize(new Dimension(560, Integer.MAX_VALUE));

        // Logo / title area
        card.add(buildTitle());
        card.add(Box.createVerticalStrut(6));
        card.add(buildSubtitle());
        card.add(Box.createVerticalStrut(24));

        // Divider
        card.add(buildDivider());
        card.add(Box.createVerticalStrut(20));

        // Author block
        card.add(buildSectionLabel("Author"));
        card.add(Box.createVerticalStrut(8));
        card.add(buildAuthorBlock());
        card.add(Box.createVerticalStrut(20));

        // Divider
        card.add(buildDivider());
        card.add(Box.createVerticalStrut(20));

        // Links block
        card.add(buildSectionLabel("Links"));
        card.add(Box.createVerticalStrut(10));
        card.add(buildLinkRow("🌐", "majdak.online",  "https://majdak.online"));
        card.add(Box.createVerticalStrut(6));
        card.add(buildLinkRow("🔒", "baluarte.pl",    "https://baluarte.pl"));
        card.add(Box.createVerticalStrut(6));
        card.add(buildLinkRow("🐙", "github.com/przemyslvw", "https://github.com/przemyslvw"));
        card.add(Box.createVerticalStrut(20));

        // Divider
        card.add(buildDivider());
        card.add(Box.createVerticalStrut(20));

        // Version / license
        card.add(buildSectionLabel("About"));
        card.add(Box.createVerticalStrut(8));
        card.add(buildInfoLine("Version", "1.0.0"));
        card.add(Box.createVerticalStrut(4));
        card.add(buildInfoLine("License", "MIT"));
        card.add(Box.createVerticalStrut(4));
        card.add(buildInfoLine("Requires", "Burp Suite 2023.1.1+ · Java 17+"));
        card.add(Box.createVerticalStrut(4));
        card.add(buildInfoLine("API", "Montoya API 2026.4"));

        return card;
    }

    // ── Component builders ─────────────────────────────────────────────────────

    private JLabel buildTitle() {
        JLabel lbl = new JLabel("ReconMaster Pro");
        lbl.setFont(new Font("SansSerif", Font.BOLD, 22));
        lbl.setForeground(ACCENT);
        lbl.setAlignmentX(Component.LEFT_ALIGNMENT);
        return lbl;
    }

    private JLabel buildSubtitle() {
        JLabel lbl = new JLabel("Automated reconnaissance for Burp Suite · Powered by the Montoya API");
        lbl.setFont(new Font("SansSerif", Font.PLAIN, 12));
        lbl.setForeground(Color.GRAY);
        lbl.setAlignmentX(Component.LEFT_ALIGNMENT);
        return lbl;
    }

    private JSeparator buildDivider() {
        JSeparator sep = new JSeparator(SwingConstants.HORIZONTAL);
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        sep.setAlignmentX(Component.LEFT_ALIGNMENT);
        return sep;
    }

    private JLabel buildSectionLabel(String text) {
        JLabel lbl = new JLabel(text.toUpperCase());
        lbl.setFont(new Font("SansSerif", Font.BOLD, 10));
        lbl.setForeground(Color.GRAY);
        lbl.setAlignmentX(Component.LEFT_ALIGNMENT);
        return lbl;
    }

    private JEditorPane buildAuthorBlock() {
        String html = "<html><body style='font-family:sans-serif;font-size:12px;margin:0;padding:0;'>" +
                "<b>Przemysław Majdak</b>" +
                "<span style='color:gray;'>  &middot;  </span>" +
                "<a href='mailto:majdak.przemyslaw@gmail.com'>majdak.przemyslaw@gmail.com</a>" +
                "</body></html>";
        return makeHtmlPane(html);
    }

    private JEditorPane buildLinkRow(String icon, String label, String url) {
        String html = "<html><body style='font-family:sans-serif;font-size:13px;margin:0;padding:0;'>" +
                icon + "&nbsp;&nbsp;<a href='" + url + "'>" + label + "</a>" +
                "</body></html>";
        return makeHtmlPane(html);
    }

    private JPanel buildInfoLine(String key, String value) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel keyLbl = new JLabel(key + ": ");
        keyLbl.setFont(new Font("SansSerif", Font.BOLD, 12));

        JLabel valLbl = new JLabel(value);
        valLbl.setFont(new Font("SansSerif", Font.PLAIN, 12));

        row.add(keyLbl);
        row.add(valLbl);
        return row;
    }

    /**
     * Creates a non-editable JEditorPane that reliably renders HTML and opens
     * hyperlinks in the system browser via HyperlinkListener.
     * JLabel HTML rendering can be suppressed by Burp Suite's custom LAF;
     * JEditorPane always renders HTML correctly.
     */
    private JEditorPane makeHtmlPane(String html) {
        JEditorPane pane = new JEditorPane("text/html", html);
        pane.setEditable(false);
        pane.setOpaque(false);
        pane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        pane.setFont(new Font("SansSerif", Font.PLAIN, 12));
        pane.setAlignmentX(Component.LEFT_ALIGNMENT);
        pane.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                openUrl(e.getURL() != null ? e.getURL().toString() : e.getDescription());
            }
        });
        return pane;
    }

    private static void openUrl(String url) {
        try {
            Desktop.getDesktop().browse(new URI(url));
        } catch (IOException | java.net.URISyntaxException ex) {
            JOptionPane.showMessageDialog(null,
                    "Cannot open link:\n" + url,
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
