package burp.ui.utils;

import javax.swing.*;
import java.awt.Color;

public class ThemeColors {

    public static Color background() {
        Color c = UIManager.getColor("TextPane.background");
        if (c == null) c = UIManager.getColor("Panel.background");
        return c != null ? c : Color.WHITE;
    }

    public static Color foreground() {
        Color c = UIManager.getColor("TextPane.foreground");
        if (c == null) c = UIManager.getColor("Label.foreground");
        return c != null ? c : Color.BLACK;
    }

    public static boolean isDark() {
        Color bg = background();
        return (bg.getRed() + bg.getGreen() + bg.getBlue()) / 3 < 128;
    }

    public static String toHex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }
}
