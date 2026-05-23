package burp.ui.utils;

import burp.ReconMasterPro;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Function;

public class ContextMenuFactory {

    public static void addContextMenu(JTable table,
                                      Function<Integer, HttpRequestResponse> requestRetriever,
                                      Function<Integer, String> urlRetriever) {
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showPopup(e);
            }

            private void showPopup(MouseEvent e) {
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && row < table.getRowCount()) {
                    table.setRowSelectionInterval(row, row);
                } else {
                    table.clearSelection();
                }

                int viewRow = table.getSelectedRow();
                if (viewRow < 0) return;
                int modelRow = table.convertRowIndexToModel(viewRow);

                HttpRequestResponse messageInfo = requestRetriever.apply(modelRow);
                String url = urlRetriever.apply(modelRow);

                JPopupMenu popup = new JPopupMenu();

                // Send to Repeater
                JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
                sendToRepeater.addActionListener(ae -> {
                    sendToTool(messageInfo, url, "Repeater");
                });
                popup.add(sendToRepeater);

                // Send to Intruder
                JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
                sendToIntruder.addActionListener(ae -> {
                    sendToTool(messageInfo, url, "Intruder");
                });
                popup.add(sendToIntruder);

                // Send to Comparer
                JMenuItem sendToComparer = new JMenuItem("Send to Comparer");
                sendToComparer.addActionListener(ae -> {
                    HttpRequestResponse targetMsg = messageInfo;
                    if (targetMsg == null && url != null) {
                        targetMsg = buildFallbackRequest(url);
                    }
                    if (targetMsg != null) {
                        if (ReconMasterPro.api != null) {
                            if (targetMsg.request() != null) {
                                ReconMasterPro.api.comparer().sendToComparer(targetMsg.request().toByteArray());
                            }
                            if (targetMsg.response() != null) {
                                ReconMasterPro.api.comparer().sendToComparer(targetMsg.response().toByteArray());
                            }
                        }
                    }
                });
                popup.add(sendToComparer);

                popup.addSeparator();

                // Copy URL
                JMenuItem copyUrl = new JMenuItem("Copy URL");
                copyUrl.addActionListener(ae -> {
                    if (url != null) {
                        Toolkit.getDefaultToolkit().getSystemClipboard()
                                .setContents(new StringSelection(url), null);
                    }
                });
                popup.add(copyUrl);

                // Copy Request (as curl)
                JMenuItem copyCurl = new JMenuItem("Copy Request (as curl)");
                copyCurl.addActionListener(ae -> {
                    String curlCmd = getCurlCommand(messageInfo, url);
                    if (curlCmd != null) {
                        Toolkit.getDefaultToolkit().getSystemClipboard()
                                .setContents(new StringSelection(curlCmd), null);
                    }
                });
                popup.add(copyCurl);

                popup.show(e.getComponent(), e.getX(), e.getY());
            }
        });
    }

    private static HttpRequestResponse buildFallbackRequest(String urlStr) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(urlStr);
            return HttpRequestResponse.httpRequestResponse(request, null);
        } catch (Exception ex) {
            if (ReconMasterPro.api != null) {
                ReconMasterPro.api.logging().logToError("Failed to build fallback request: " + ex.getMessage());
            }
            return null;
        }
    }

    private static void sendToTool(HttpRequestResponse messageInfo, String urlStr, String tool) {
        try {
            HttpRequestResponse targetMsg = messageInfo;

            // Fallback
            if (targetMsg == null && urlStr != null) {
                targetMsg = buildFallbackRequest(urlStr);
            }

            if (targetMsg != null && ReconMasterPro.api != null) {
                if (tool.equals("Repeater")) {
                    ReconMasterPro.api.repeater().sendToRepeater(targetMsg.request(), "ReconMaster");
                } else if (tool.equals("Intruder")) {
                    ReconMasterPro.api.intruder().sendToIntruder(targetMsg.request());
                }
            }
        } catch (Exception ex) {
            if (ReconMasterPro.api != null) {
                ReconMasterPro.api.logging().logToError("Failed to send to " + tool + ": " + ex.getMessage());
            }
        }
    }

    private static String getCurlCommand(HttpRequestResponse messageInfo, String urlStr) {
        if (messageInfo == null || messageInfo.request() == null) {
            if (urlStr != null) {
                return "curl -i -s -k '" + urlStr.replace("'", "'\\''") + "'";
            }
            return null;
        }
        try {
            HttpRequest request = messageInfo.request();
            StringBuilder curl = new StringBuilder("curl -i -s -k");
            curl.append(" -X ").append(request.method());

            // headers
            for (var header : request.headers()) {
                String hStr = header.toString();
                // skip HTTP/1.1 first line
                if (hStr.startsWith("GET ") || hStr.startsWith("POST ") || hStr.startsWith("PUT ") || hStr.startsWith("DELETE ") || hStr.startsWith("OPTIONS ") || hStr.startsWith("PATCH ") || hStr.startsWith("HEAD ")) {
                    continue;
                }
                curl.append(" -H '").append(hStr.replace("'", "'\\''")).append("'");
            }

            // body
            String body = request.bodyToString();
            if (body != null && !body.isEmpty()) {
                curl.append(" --data-binary '").append(body.replace("'", "'\\''")).append("'");
            }

            String url = request.url();
            if (url == null) url = urlStr;
            if (url != null) {
                curl.append(" '").append(url.replace("'", "'\\''")).append("'");
            }
            return curl.toString();
        } catch (Exception e) {
            if (urlStr != null) {
                return "curl -i -s -k '" + urlStr.replace("'", "'\\''") + "'";
            }
            return null;
        }
    }
}
