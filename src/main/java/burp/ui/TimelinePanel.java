package burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.models.TimelineEvent;
import burp.utils.DatabaseManager;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class TimelinePanel extends JPanel {

    private static final String[] COLUMNS =
        {"Time", "Type", "Severity", "Host", "Message"};

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final MontoyaApi api;
    private final DefaultTableModel model;
    private final List<TimelineEvent> events = new ArrayList<>();
    private final JLabel badgeLabel;
    private int unseenCount = 0;

    // opcjonalnie: DatabaseManager do query historii
    private DatabaseManager db;

    public TimelinePanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;

        model = new DefaultTableModel(COLUMNS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };

        JTable table = new JTable(model);
        table.setAutoCreateRowSorter(false); // utrzymuj porządek chronologiczny
        table.getColumnModel().getColumn(0).setPreferredWidth(70);   // Time
        table.getColumnModel().getColumn(1).setPreferredWidth(140);  // Type
        table.getColumnModel().getColumn(2).setPreferredWidth(70);   // Severity
        table.getColumnModel().getColumn(3).setPreferredWidth(150);  // Host
        table.getColumnModel().getColumn(4).setPreferredWidth(500);  // Message

        table.setDefaultRenderer(Object.class, new SeverityCellRenderer());

        burp.ui.utils.ContextMenuFactory.addContextMenu(table,
            row -> null, // Timeline events don't store originalRequestResponse directly
            row -> {
                synchronized (events) {
                    if (row >= 0 && row < events.size()) {
                        TimelineEvent event = events.get(row);
                        String msg = event.message;
                        if (msg != null) {
                            int httpIdx = msg.indexOf("http://");
                            if (httpIdx == -1) httpIdx = msg.indexOf("https://");
                            if (httpIdx != -1) {
                                int endIdx = msg.indexOf(' ', httpIdx);
                                if (endIdx == -1) endIdx = msg.length();
                                return msg.substring(httpIdx, endIdx);
                            }
                        }
                        return "https://" + event.host + "/";
                    }
                }
                return null;
            }
        );

        // toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        badgeLabel = new JLabel("Events: 0");
        badgeLabel.setFont(badgeLabel.getFont().deriveFont(Font.BOLD));

        JComboBox<String> timeFilter = new JComboBox<>(
            new String[]{"Last 5 min", "Last 15 min", "Last 1 hour", "All"});
        JTextField hostFilter = new JTextField(15);
        hostFilter.putClientProperty("JTextField.placeholderText", "Filter host...");

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> clearTable());

        JButton refreshBtn = new JButton("Reload from DB");
        refreshBtn.addActionListener(e -> reloadFromDb(getMinutes(timeFilter)));

        toolbar.add(new JLabel("Window:"));
        toolbar.add(timeFilter);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(new JLabel("Host:"));
        toolbar.add(hostFilter);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(badgeLabel);
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(refreshBtn);
        toolbar.add(clearBtn);

        // live filtr po hoście
        hostFilter.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filterByHost(table, hostFilter.getText()); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filterByHost(table, hostFilter.getText()); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) {}
        });

        add(toolbar, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    public void setDatabase(DatabaseManager db) {
        this.db = db;
    }

    /**
     * Wywoływana z TimelineAnalyzer → push nowego eventu.
     * Musi być thread-safe (wywoływana z wątku tła).
     */
    public void addEvent(TimelineEvent event) {
        SwingUtilities.invokeLater(() -> {
            events.add(event);
            model.addRow(new Object[]{
                FMT.format(event.timestamp),
                formatType(event.eventType),
                event.severity,
                event.host,
                event.message
            });

            unseenCount++;
            badgeLabel.setText("Events: " + model.getRowCount() +
                (unseenCount > 0 ? "  (" + unseenCount + " new)" : ""));

            // auto-scroll do najnowszego wiersza
            int last = model.getRowCount() - 1;
            // dostęp przez JScrollPane wymaga referencji do table — wystarczy invokeLater
        });
    }

    private void clearTable() {
        model.setRowCount(0);
        events.clear();
        unseenCount = 0;
        badgeLabel.setText("Events: 0");
    }

    private void reloadFromDb(int minutes) {
        if (db == null) return;
        clearTable();
        List<TimelineEvent> history = db.getRecentEvents(minutes);
        // getRecentEvents zwraca od najnowszego — odwróć dla chronologicznego widoku
        for (int i = history.size() - 1; i >= 0; i--) {
            addEvent(history.get(i));
        }
        unseenCount = 0;
        badgeLabel.setText("Events: " + model.getRowCount());
    }

    private void filterByHost(JTable table, String text) {
        TableRowSorter<?> sorter = (TableRowSorter<?>) table.getRowSorter();
        if (sorter == null) return;
        sorter.setRowFilter(text.isEmpty() ? null
            : RowFilter.regexFilter("(?i)" + text, 3));
    }

    private int getMinutes(JComboBox<String> combo) {
        switch (combo.getSelectedIndex()) {
            case 0: return 5;
            case 1: return 15;
            case 2: return 60;
            default: return Integer.MAX_VALUE / 60;
        }
    }

    private String formatType(String eventType) {
        switch (eventType) {
            case "NEW_ENDPOINT":       return "New Endpoint";
            case "ENDPOINT_CHANGED":   return "Status Changed";
            case "HIGH_RISK_ENDPOINT": return "High Risk";
            case "NEW_TECH":           return "New Technology";
            case "NEW_SECRET":         return "SECRET FOUND";
            default:                   return eventType;
        }
    }

    private static class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(
                table, value, selected, focus, row, column);
            if (!selected) {
                String sev = (String) table.getValueAt(row, 2);
                String sevStr = sev != null ? sev : "";
                Color bg = Color.WHITE;
                switch (sevStr) {
                    case "CRITICAL": bg = new Color(255, 160, 160); break;
                    case "HIGH":     bg = new Color(255, 200, 150); break;
                    case "MEDIUM":   bg = new Color(255, 240, 170); break;
                    case "LOW":      bg = new Color(210, 235, 210); break;
                }
                c.setBackground(bg);
            }
            return c;
        }
    }
}
