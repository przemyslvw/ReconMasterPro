package burp.ui.utils;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

public class CodeBlockPanel extends JPanel {

    private final String codeContent;

    public CodeBlockPanel(String language, String code) {
        this.codeContent = code != null ? code.trim() : "";
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createLineBorder(new Color(0x3e, 0x3e, 0x3e), 1));
        setBackground(new Color(0x20, 0x20, 0x20));

        // --- Header Panel ---
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(0x18, 0x18, 0x18));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));

        String langName = (language == null || language.trim().isEmpty()) ? "CODE" : language.trim().toUpperCase();
        JLabel langLabel = new JLabel(langName);
        langLabel.setFont(new Font("SansSerif", Font.BOLD, 10));
        langLabel.setForeground(new Color(0xaa, 0xaa, 0xaa));

        JButton copyButton = new JButton("Copy");
        copyButton.setFont(new Font("SansSerif", Font.PLAIN, 10));
        copyButton.setFocusPainted(false);
        copyButton.setMargin(new Insets(2, 6, 2, 6));
        copyButton.setBackground(new Color(0x2d, 0x2d, 0x2d));
        copyButton.setForeground(new Color(0xee, 0xee, 0xee));
        copyButton.setBorder(BorderFactory.createLineBorder(new Color(0x44, 0x44, 0x44), 1));

        copyButton.addActionListener(e -> {
            try {
                StringSelection selection = new StringSelection(codeContent);
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selection, selection);

                copyButton.setText("Copied!");
                copyButton.setForeground(new Color(0x50, 0xc8, 0x78)); // Emerald green color

                Timer timer = new Timer(1500, evt -> {
                    copyButton.setText("Copy");
                    copyButton.setForeground(new Color(0xee, 0xee, 0xee));
                });
                timer.setRepeats(false);
                timer.start();
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Failed to copy code: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        headerPanel.add(langLabel, BorderLayout.WEST);
        headerPanel.add(copyButton, BorderLayout.EAST);

        // --- Code Content Area ---
        JTextArea codeArea = new JTextArea(codeContent);
        codeArea.setEditable(false);
        codeArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        codeArea.setBackground(new Color(0x20, 0x20, 0x20));
        codeArea.setForeground(new Color(0xdc, 0xdc, 0xdc));
        codeArea.setCaretColor(Color.WHITE);
        codeArea.setLineWrap(true);
        codeArea.setWrapStyleWord(true);
        codeArea.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        add(headerPanel, BorderLayout.NORTH);
        add(codeArea, BorderLayout.CENTER);
    }
}
