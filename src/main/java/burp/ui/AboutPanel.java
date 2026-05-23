package burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
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
        card.add(buildLinkRow("🐙", "GitHub — przemyslvw", "https://github.com/przemyslvw"));
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

    private JPanel buildAuthorBlock() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel nameLabel = new JLabel("Przemysław Majdak");
        nameLabel.setFont(new Font("SansSerif", Font.BOLD, 13));

        JLabel sep = new JLabel("  ·  ");
        sep.setForeground(Color.GRAY);

        JLabel emailLabel = makeLink("majdak.przemyslaw@gmail.com", "mailto:majdak.przemyslaw@gmail.com");

        row.add(nameLabel);
        row.add(sep);
        row.add(emailLabel);
        return row;
    }

    private JPanel buildLinkRow(String icon, String label, String url) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel iconLbl = new JLabel(icon);
        iconLbl.setFont(new Font("SansSerif", Font.PLAIN, 14));

        JLabel link = makeLink(label, url);
        link.setFont(new Font("SansSerif", Font.PLAIN, 13));

        row.add(iconLbl);
        row.add(link);
        return row;
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

    /** Clickable hyperlink label that opens a URL in the default browser. */
    private JLabel makeLink(String text, String url) {
        JLabel lbl = new JLabel("<html><a href=''>" + text + "</a></html>");
        lbl.setForeground(LINK_COLOR);
        lbl.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        lbl.setFont(new Font("SansSerif", Font.PLAIN, 12));
        lbl.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                openUrl(url);
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                lbl.setForeground(ACCENT);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                lbl.setForeground(LINK_COLOR);
            }
        });
        return lbl;
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
