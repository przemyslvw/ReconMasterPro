package burp.ui.utils;

import java.util.ArrayList;
import java.util.List;

public class MarkdownRenderer {

    private MarkdownRenderer() {}

    public static String toHtml(String md) {
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
                sb.append("<li>").append(replaceFormatting(trimmed.substring(2))).append("</li>");
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
                if (trimmed.matches("^\\|[\\s\\-:\\|]+$")) continue; // separator row

                String[] cells = trimmed.split("\\|");
                List<String> validCells = new ArrayList<>();
                int start = 1;
                int end = cells.length - 1;
                for (int i = start; i < end; i++) validCells.add(cells[i].trim());

                sb.append("<tr>");
                for (String cell : validCells) {
                    String tag = hasTableHeader ? "td" : "th";
                    sb.append("<").append(tag).append(">")
                      .append(replaceFormatting(cell))
                      .append("</").append(tag).append(">");
                }
                sb.append("</tr>");
                hasTableHeader = true;
                continue;
            } else {
                if (inTable) {
                    sb.append("</table>");
                    inTable = false;
                }
            }

            // Headers
            if (trimmed.startsWith("### ")) {
                sb.append("<h3>").append(replaceFormatting(trimmed.substring(4))).append("</h3>");
            } else if (trimmed.startsWith("## ")) {
                sb.append("<h2>").append(replaceFormatting(trimmed.substring(3))).append("</h2>");
            } else if (trimmed.startsWith("# ")) {
                sb.append("<h1>").append(replaceFormatting(trimmed.substring(2))).append("</h1>");
            } else if (!trimmed.isEmpty()) {
                sb.append("<p>").append(replaceFormatting(trimmed)).append("</p>");
            }
        }

        if (inList)  sb.append("</ul>");
        if (inTable) sb.append("</table>");

        return sb.toString();
    }

    public static String replaceFormatting(String text) {
        if (text == null) return "";
        text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        text = text.replaceAll("`([^`]+)`", "<code>$1</code>");
        text = text.replaceAll("\\*\\*([^*]+)\\*\\*", "<b>$1</b>");
        text = text.replaceAll("\\*([^*]+)\\*", "<i>$1</i>");
        return text;
    }
}
