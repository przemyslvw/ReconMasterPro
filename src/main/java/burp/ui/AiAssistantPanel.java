package burp.ui;

import burp.models.*;
import burp.modules.AiAnalyzer;
import burp.modules.AiClient;
import burp.ui.utils.CodeBlockPanel;
import burp.utils.SettingsManager;
import burp.utils.AiProvider;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

public class AiAssistantPanel extends JPanel {

    private final SettingsManager settings;
    private final AiClient aiClient;
    private final AiAnalyzer aiAnalyzer;

    // Checkboxes
    private final JCheckBox techCheck;
    private final JCheckBox endpointsCheck;
    private final JCheckBox corsCheck;
    private final JCheckBox graphqlCheck;
    private final JCheckBox cloudCheck;
    private final JCheckBox secretsCheck;

    // OpSec Info Panel
    private final JPanel opsecInfoPanel;

    // Right Pane - Card Layout
    private final JPanel rightPanel;
    private final CardLayout rightLayout;
    private final JPanel resultsContainer;
    private final JLabel loadingStatusLabel;

    public AiAssistantPanel(
            SettingsManager settings,
            Supplier<List<Endpoint>> endpointSupplier,
            Supplier<List<Technology>> techSupplier,
            Supplier<List<Secret>> secretSupplier,
            Supplier<List<CorsFinding>> corsSupplier,
            Supplier<List<CloudAsset>> cloudSupplier,
            Supplier<List<GraphQLEndpoint>> graphqlSupplier) {
        super(new BorderLayout());
        this.settings = settings;
        this.aiClient = new AiClient(settings);
        this.aiAnalyzer = new AiAnalyzer(
                settings,
                endpointSupplier,
                techSupplier,
                secretSupplier,
                corsSupplier,
                cloudSupplier,
                graphqlSupplier
        );

        // ── Left Configuration Panel ─────────────────────────────────────────
        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Group 1: Data Modules Selection
        JPanel modulesGroup = new JPanel(new GridLayout(6, 1, 4, 4));
        modulesGroup.setBorder(new TitledBorder("Select Recon Data to Analyze"));

        techCheck = new JCheckBox("Technologies & CVEs", true);
        endpointsCheck = new JCheckBox("Endpoints", true);
        corsCheck = new JCheckBox("CORS Misconfigurations", true);
        graphqlCheck = new JCheckBox("GraphQL Endpoints", true);
        cloudCheck = new JCheckBox("Cloud Assets", true);
        secretsCheck = new JCheckBox("Secrets Scanner", true);

        modulesGroup.add(techCheck);
        modulesGroup.add(endpointsCheck);
        modulesGroup.add(corsCheck);
        modulesGroup.add(graphqlCheck);
        modulesGroup.add(cloudCheck);
        modulesGroup.add(secretsCheck);

        // Group 2: OpSec & Privacy Info
        opsecInfoPanel = new JPanel();
        opsecInfoPanel.setBorder(new TitledBorder("Privacy & OpSec Info"));
        updateOpSecPanel();

        // Run Analysis Button
        JButton runBtn = new JButton("Analyze Attack Surface");
        runBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        runBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        runBtn.setMaximumSize(new Dimension(Short.MAX_VALUE, 40));
        runBtn.setBackground(new Color(0xff, 0x66, 0x00)); // burp orange
        runBtn.setForeground(Color.WHITE);
        runBtn.setFocusPainted(false);
        runBtn.addActionListener(e -> runAnalysis());

        leftPanel.add(modulesGroup);
        leftPanel.add(Box.createVerticalStrut(10));
        leftPanel.add(opsecInfoPanel);
        leftPanel.add(Box.createVerticalStrut(10));
        leftPanel.add(runBtn);
        leftPanel.add(Box.createVerticalGlue());

        JScrollPane leftScroll = new JScrollPane(leftPanel);
        leftScroll.setMinimumSize(new Dimension(300, 200));
        leftScroll.setPreferredSize(new Dimension(320, 400));
        leftScroll.setBorder(BorderFactory.createEmptyBorder());
        leftScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        // ── Right Panel (Card Layout) ────────────────────────────────────────
        rightLayout = new CardLayout();
        rightPanel = new JPanel(rightLayout);

        // Card 1: Initial/Empty State
        JPanel initialCard = new JPanel(new GridBagLayout());
        JLabel initialLabel = new JLabel("<html><center>No analysis has been run yet.<br/>Configure findings on the left, then click <b>Analyze Attack Surface</b>.</center></html>");
        initialLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        initialLabel.setForeground(Color.GRAY);
        initialCard.add(initialLabel);

        // Card 2: Loading State
        JPanel loadingCard = new JPanel(new GridBagLayout());
        GridBagConstraints lc = new GridBagConstraints();
        lc.gridx = 0; lc.gridy = GridBagConstraints.RELATIVE;
        lc.insets = new Insets(8, 8, 8, 8);

        JProgressBar progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setPreferredSize(new Dimension(220, 16));

        JLabel loadingTitle = new JLabel("AI Agent Analyzing Attack Surface...");
        loadingTitle.setFont(new Font("SansSerif", Font.BOLD, 13));

        loadingStatusLabel = new JLabel("Aggregating reconnaissance findings...");
        loadingStatusLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        loadingStatusLabel.setForeground(Color.GRAY);

        loadingCard.add(loadingTitle, lc);
        loadingCard.add(progressBar, lc);
        loadingCard.add(loadingStatusLabel, lc);

        // Card 3: Results State
        resultsContainer = new JPanel();
        resultsContainer.setLayout(new BoxLayout(resultsContainer, BoxLayout.Y_AXIS));
        resultsContainer.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JScrollPane resultsScroll = new JScrollPane(resultsContainer);
        resultsScroll.getVerticalScrollBar().setUnitIncrement(16);
        resultsScroll.setBorder(BorderFactory.createEmptyBorder());

        rightPanel.add(initialCard, "INITIAL");
        rightPanel.add(loadingCard, "LOADING");
        rightPanel.add(resultsScroll, "RESULTS");

        rightLayout.show(rightPanel, "INITIAL");

        // ── Main SplitPane ───────────────────────────────────────────────────
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightPanel);
        splitPane.setDividerLocation(320);
        splitPane.setBorder(BorderFactory.createEmptyBorder());

        add(splitPane, BorderLayout.CENTER);
    }

    public void refreshSettings() {
        updateOpSecPanel();
    }

    private void updateOpSecPanel() {
        opsecInfoPanel.removeAll();
        opsecInfoPanel.setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        c.weightx = 1.0;
        c.gridx = 0; c.gridy = 0;
        c.insets = new Insets(3, 8, 3, 8);

        AiProvider provider = settings.getAiProvider();
        String model = settings.getAiModel();
        boolean maskSecrets = settings.isAiMaskSecrets();
        boolean maskDomains = settings.isAiMaskDomains();

        opsecInfoPanel.add(makeHtmlLabel("<b>AI Provider:</b> " + provider.name()), c);
        c.gridy++;
        opsecInfoPanel.add(makeHtmlLabel("<b>Model Name:</b> " + model), c);
        c.gridy++;
        opsecInfoPanel.add(makeHtmlLabel("<b>Mask Secrets:</b> " + (maskSecrets ? "Yes" : "No")), c);
        c.gridy++;
        opsecInfoPanel.add(makeHtmlLabel("<b>Mask Domains:</b> " + (maskDomains ? "Yes" : "No")), c);
        c.gridy++;

        // Gap before warning box
        c.insets = new Insets(10, 8, 4, 8);

        JPanel warningBox = new JPanel(new BorderLayout());
        warningBox.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(provider == AiProvider.LOCAL ? new Color(0x50, 0xc8, 0x78) : new Color(0xff, 0x99, 0x00), 1),
                BorderFactory.createEmptyBorder(8, 8, 8, 8)
        ));

        // Adjust warning background based on Dark/Light Theme
        Color panelBg = UIManager.getColor("Panel.background");
        boolean isDark = panelBg != null && (panelBg.getRed() + panelBg.getGreen() + panelBg.getBlue()) / 3 < 128;
        if (isDark) {
            warningBox.setBackground(provider == AiProvider.LOCAL ? new Color(0x1a, 0x33, 0x22) : new Color(0x33, 0x22, 0x00));
        } else {
            warningBox.setBackground(provider == AiProvider.LOCAL ? new Color(0xf0, 0xf9, 0xf4) : new Color(0xff, 0xf9, 0xe6));
        }

        String warningHtml;
        if (provider == AiProvider.LOCAL) {
            warningHtml = "<html><body style='font-family:sans-serif;font-size:11px;'>" +
                    "<font color='#50c878'><b>&#x1F6E1;&#xFE0F; Local Mode Active</b></font><br>" +
                    "Using local Ollama endpoint (" + settings.getAiLocalUrl() + ").<br>" +
                    "Recon data remains private and does not leave your machine." +
                    "</body></html>";
        } else {
            warningHtml = "<html><body style='font-family:sans-serif;font-size:11px;'>" +
                    "<font color='#ff9900'><b>&#x26A0;&#xFE0F; Cloud Provider Active</b></font><br>" +
                    "Using cloud API (" + provider.name() + "). Selected findings data will be transmitted.<br>" +
                    "<b>Recommendation:</b> Use local model (e.g. Ollama with <b>llama3</b> or <b>mistral</b>) in Settings for highly confidential systems." +
                    "</body></html>";
        }

        JEditorPane warningText = new JEditorPane("text/html", warningHtml) {
            @Override
            public boolean getScrollableTracksViewportWidth() {
                return true; // force wrap to parent width — no horizontal overflow
            }
            @Override
            public Dimension getPreferredSize() {
                Dimension d = super.getPreferredSize();
                // clamp width to parent container so text wraps properly
                Container parent = getParent();
                if (parent != null) {
                    d.width = parent.getWidth() - 20;
                }
                return d;
            }
        };
        warningText.setEditable(false);
        warningText.setOpaque(false);
        warningText.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        warningText.setFont(new Font("SansSerif", Font.PLAIN, 11));
        if (isDark) {
            warningText.setForeground(Color.WHITE);
        } else {
            warningText.setForeground(Color.BLACK);
        }

        warningBox.add(warningText, BorderLayout.CENTER);
        opsecInfoPanel.add(warningBox, c);

        opsecInfoPanel.revalidate();
        opsecInfoPanel.repaint();
    }

    private void runAnalysis() {
        boolean includeTech = techCheck.isSelected();
        boolean includeEndpoints = endpointsCheck.isSelected();
        boolean includeCors = corsCheck.isSelected();
        boolean includeGraphql = graphqlCheck.isSelected();
        boolean includeCloud = cloudCheck.isSelected();
        boolean includeSecrets = secretsCheck.isSelected();

        if (!includeTech && !includeEndpoints && !includeCors && !includeGraphql && !includeCloud && !includeSecrets) {
            JOptionPane.showMessageDialog(this,
                    "Please select at least one data module to analyze.",
                    "No Data Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        rightLayout.show(rightPanel, "LOADING");
        loadingStatusLabel.setText("Aggregating reconnaissance findings...");

        String systemPrompt = aiAnalyzer.buildSystemPrompt();
        String userPrompt = aiAnalyzer.buildUserPrompt(includeEndpoints, includeTech, includeSecrets, includeCors, includeCloud, includeGraphql);

        loadingStatusLabel.setText("Connecting to " + settings.getAiProvider() + " API...");

        aiClient.sendPromptAsync(systemPrompt, userPrompt, new AiClient.AiCallback() {
            @Override
            public void onSuccess(String response) {
                SwingUtilities.invokeLater(() -> {
                    displayMarkdown(response);
                    rightLayout.show(rightPanel, "RESULTS");
                });
            }

            @Override
            public void onFailure(Throwable t) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(AiAssistantPanel.this,
                            "AI Analysis failed:\n" + t.getMessage(),
                            "Analysis Error", JOptionPane.ERROR_MESSAGE);
                    rightLayout.show(rightPanel, "INITIAL");
                });
            }
        });
    }

    private void displayMarkdown(String markdown) {
        resultsContainer.removeAll();

        // Timestamp Header Panel
        JPanel timePanel = new JPanel(new BorderLayout());
        timePanel.setBackground(resultsContainer.getBackground());
        timePanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        JLabel timeLabel = new JLabel("AI Security Report - " + sdf.format(new Date()));
        timeLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        timePanel.add(timeLabel, BorderLayout.WEST);
        resultsContainer.add(timePanel);

        if (markdown == null || markdown.trim().isEmpty()) {
            resultsContainer.add(new JLabel("No response returned from the model."));
            resultsContainer.revalidate();
            resultsContainer.repaint();
            return;
        }

        String[] lines = markdown.split("\n");
        StringBuilder currentText = new StringBuilder();
        StringBuilder currentCode = new StringBuilder();
        String currentCodeLang = "";
        boolean inCodeBlock = false;

        for (String line : lines) {
            if (line.startsWith("```")) {
                if (inCodeBlock) {
                    // Code block ended
                    addTextBlock(currentText.toString());
                    currentText.setLength(0);

                    addCodeBlock(currentCodeLang, currentCode.toString());
                    currentCode.setLength(0);
                    currentCodeLang = "";
                    inCodeBlock = false;
                } else {
                    // Code block started
                    addTextBlock(currentText.toString());
                    currentText.setLength(0);

                    currentCodeLang = line.substring(3).trim();
                    inCodeBlock = true;
                }
            } else {
                if (inCodeBlock) {
                    currentCode.append(line).append("\n");
                } else {
                    currentText.append(line).append("\n");
                }
            }
        }

        // Add final leftovers
        if (inCodeBlock) {
            addCodeBlock(currentCodeLang, currentCode.toString());
        } else {
            addTextBlock(currentText.toString());
        }

        resultsContainer.revalidate();
        resultsContainer.repaint();
    }

    private void addTextBlock(String md) {
        if (md == null || md.trim().isEmpty()) return;

        String html = convertMarkdownToHtml(md);

        JTextPane textPane = new JTextPane();
        textPane.setContentType("text/html");
        textPane.setEditable(false);
        textPane.setBackground(resultsContainer.getBackground());
        textPane.setMargin(new Insets(6, 6, 6, 6));

        // Dynamically style based on Burp theme color
        Color bg = UIManager.getColor("TextPane.background");
        if (bg == null) bg = UIManager.getColor("Panel.background");
        if (bg == null) bg = Color.WHITE;

        Color fg = UIManager.getColor("TextPane.foreground");
        if (fg == null) fg = UIManager.getColor("Label.foreground");
        if (fg == null) fg = Color.BLACK;

        String bgHex = String.format("#%02x%02x%02x", bg.getRed(), bg.getGreen(), bg.getBlue());
        String fgHex = String.format("#%02x%02x%02x", fg.getRed(), fg.getGreen(), fg.getBlue());

        boolean isDark = (bg.getRed() + bg.getGreen() + bg.getBlue()) / 3 < 128;
        String borderHex = isDark ? "#444444" : "#dddddd";
        String headerBgHex = isDark ? "#2d2d2d" : "#f2f2f2";
        String codeBgHex = isDark ? "#282828" : "#f5f5f5";
        String evenRowBgHex = isDark ? "#232323" : "#fafafa";

        String styledHtml = "<html><head><style>" +
                "body { font-family: sans-serif; font-size: 11px; color: " + fgHex + "; margin: 0; }" +
                "h1 { font-size: 14px; color: " + fgHex + "; border-bottom: 1px solid " + borderHex + "; padding-bottom: 3px; margin-top: 14px; margin-bottom: 6px; }" +
                "h2 { font-size: 12px; color: " + fgHex + "; border-bottom: 1px solid " + borderHex + "; padding-bottom: 2px; margin-top: 10px; margin-bottom: 4px; }" +
                "h3 { font-size: 11px; color: " + fgHex + "; margin-top: 8px; margin-bottom: 2px; }" +
                "table { border-collapse: collapse; width: 100%; margin-bottom: 8px; margin-top: 4px; }" +
                "th { background-color: " + headerBgHex + "; border: 1px solid " + borderHex + "; padding: 4px; text-align: left; font-weight: bold; color: " + fgHex + "; }" +
                "td { border: 1px solid " + borderHex + "; padding: 4px; color: " + fgHex + "; }" +
                "tr:nth-child(even) { background-color: " + evenRowBgHex + "; }" +
                "ul { margin-top: 2px; margin-bottom: 2px; padding-left: 16px; }" +
                "li { margin-bottom: 1px; }" +
                "p { margin-top: 2px; margin-bottom: 2px; }" +
                "code { background-color: " + codeBgHex + "; padding: 1px 2px; font-family: monospaced; font-size: 9px; border-radius: 2px; color: " + fgHex + "; }" +
                "</style></head><body>" + html + "</body></html>";

        textPane.setText(styledHtml);
        resultsContainer.add(textPane);
        resultsContainer.add(Box.createVerticalStrut(4));
    }

    private void addCodeBlock(String language, String code) {
        if (code == null || code.trim().isEmpty()) return;

        CodeBlockPanel codeBlock = new CodeBlockPanel(language, code);
        // Align left and allow natural growth
        codeBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        // Wrap code block in a small margin container
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(resultsContainer.getBackground());
        wrapper.setBorder(BorderFactory.createEmptyBorder(4, 6, 6, 6));
        wrapper.add(codeBlock, BorderLayout.CENTER);
        wrapper.setMaximumSize(new Dimension(Short.MAX_VALUE, 300)); // cap height but stretch width

        resultsContainer.add(wrapper);
        resultsContainer.add(Box.createVerticalStrut(4));
    }

    private String convertMarkdownToHtml(String md) {
        if (md == null) return "";

        String[] lines = md.split("\n");
        StringBuilder sb = new StringBuilder();
        boolean inList = false;
        boolean inTable = false;
        boolean hasTableHeader = false;

        for (String line : lines) {
            String trimmed = line.trim();

            // List items
            if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
                if (!inList) {
                    sb.append("<ul>");
                    inList = true;
                }
                String content = trimmed.substring(2);
                content = replaceMarkdownFormatting(content);
                sb.append("<li>").append(content).append("</li>");
                continue;
            } else {
                if (inList) {
                    sb.append("</ul>");
                    inList = false;
                }
            }

            // Tables
            if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
                if (!inTable) {
                    sb.append("<table>");
                    inTable = true;
                    hasTableHeader = false;
                }

                if (trimmed.matches("^\\|[\\s\\-:\\|]+$")) {
                    continue; // Skip separator line
                }

                String[] cells = trimmed.split("\\|");
                List<String> validCells = new ArrayList<>();
                int startIdx = trimmed.startsWith("|") ? 1 : 0;
                int endIdx = cells.length;
                if (trimmed.endsWith("|") && cells.length > startIdx) {
                    endIdx = cells.length - 1;
                }
                for (int i = startIdx; i < endIdx; i++) {
                    validCells.add(cells[i].trim());
                }

                sb.append("<tr>");
                for (String cell : validCells) {
                    String formattedCell = replaceMarkdownFormatting(cell);
                    if (!hasTableHeader) {
                        sb.append("<th>").append(formattedCell).append("</th>");
                    } else {
                        sb.append("<td>").append(formattedCell).append("</td>");
                    }
                }
                sb.append("</tr>");

                if (!hasTableHeader) {
                    hasTableHeader = true;
                }
                continue;
            } else {
                if (inTable) {
                    sb.append("</table>");
                    inTable = false;
                }
            }

            // Headers
            if (trimmed.startsWith("### ")) {
                String content = trimmed.substring(4);
                sb.append("<h3>").append(replaceMarkdownFormatting(content)).append("</h3>");
                continue;
            } else if (trimmed.startsWith("## ")) {
                String content = trimmed.substring(3);
                sb.append("<h2>").append(replaceMarkdownFormatting(content)).append("</h2>");
                continue;
            } else if (trimmed.startsWith("# ")) {
                String content = trimmed.substring(2);
                sb.append("<h1>").append(replaceMarkdownFormatting(content)).append("</h1>");
                continue;
            }

            // Regular paragraph
            if (!trimmed.isEmpty()) {
                sb.append("<p>").append(replaceMarkdownFormatting(trimmed)).append("</p>");
            }
        }

        if (inList) sb.append("</ul>");
        if (inTable) sb.append("</table>");

        return sb.toString();
    }

    private String replaceMarkdownFormatting(String text) {
        if (text == null) return "";

        // Escape HTML
        text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");

        // Code code
        text = text.replaceAll("`([^`]+)`", "<code>$1</code>");

        // Bold
        text = text.replaceAll("\\*\\*([^\\*]+)\\*\\*", "<b>$1</b>");

        // Italic
        text = text.replaceAll("\\*([^\\*]+)\\*", "<i>$1</i>");

        return text;
    }

    /**
     * Creates a non-editable JEditorPane that renders HTML properly and wraps text
     * to the container width (prevents horizontal scrollbar in the left panel).
     * JLabel can fail to render HTML in some Burp Suite Look-and-Feel configurations.
     */
    private static JEditorPane makeHtmlLabel(String innerHtml) {
        String html = "<html><body style='font-family:sans-serif;font-size:11px;'>" + innerHtml + "</body></html>";
        JEditorPane pane = new JEditorPane("text/html", html) {
            @Override
            public boolean getScrollableTracksViewportWidth() {
                return true; // force wrap to parent width — no horizontal overflow
            }
        };
        pane.setEditable(false);
        pane.setOpaque(false);
        pane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        pane.setFont(new Font("SansSerif", Font.PLAIN, 11));
        return pane;
    }
}
