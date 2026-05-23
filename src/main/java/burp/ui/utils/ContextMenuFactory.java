package burp.ui.utils;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

public class ContextMenuFactory {

    public static void addContextMenu(JTable table, 
                                      Function<Integer, IHttpRequestResponse> requestRetriever,
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

                IHttpRequestResponse messageInfo = requestRetriever.apply(modelRow);
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
                    IHttpRequestResponse targetMsg = messageInfo;
                    if (targetMsg == null && url != null) {
                        targetMsg = buildFallbackRequest(url);
                    }
                    if (targetMsg != null) {
                        if (targetMsg.getRequest() != null) {
                            BurpExtender.callbacks.sendToComparer(targetMsg.getRequest());
                        }
                        if (targetMsg.getResponse() != null) {
                            BurpExtender.callbacks.sendToComparer(targetMsg.getResponse());
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

    private static IHttpRequestResponse buildFallbackRequest(String urlStr) {
        try {
            java.net.URL url = new java.net.URL(urlStr);
            String host = url.getHost();
            int port = url.getPort() == -1 ? (url.getProtocol().equalsIgnoreCase("https") ? 443 : 80) : url.getPort();
            boolean useHttps = url.getProtocol().equalsIgnoreCase("https");
            
            IHttpService service = BurpExtender.helpers.buildHttpService(host, port, useHttps);
            String path = url.getPath().isEmpty() ? "/" : url.getPath();
            if (url.getQuery() != null) path += "?" + url.getQuery();
            
            byte[] requestBytes = BurpExtender.helpers.buildHttpMessage(
                List.of(
                    "GET " + path + " HTTP/1.1",
                    "Host: " + host,
                    "User-Agent: Mozilla/5.0 (ReconMaster Fallback)",
                    "Connection: close"
                ),
                new byte[0]
            );
            
            return new FallbackHttpRequestResponse(service, requestBytes);
        } catch (Exception ex) {
            BurpExtender.callbacks.printError("Failed to build fallback request: " + ex.getMessage());
            return null;
        }
    }

    private static void sendToTool(IHttpRequestResponse messageInfo, String urlStr, String tool) {
        try {
            IHttpRequestResponse targetMsg = messageInfo;
            
            // Fallback: Jeśli nie mamy zapisanego requestResponse, budujemy sztuczny na podstawie URL
            if (targetMsg == null && urlStr != null) {
                targetMsg = buildFallbackRequest(urlStr);
            }
            
            if (targetMsg != null) {
                IHttpService service = targetMsg.getHttpService();
                if (tool.equals("Repeater")) {
                    BurpExtender.callbacks.sendToRepeater(
                        service.getHost(), service.getPort(), 
                        service.getProtocol().equalsIgnoreCase("https"), 
                        targetMsg.getRequest(), "ReconMaster"
                    );
                } else if (tool.equals("Intruder")) {
                    BurpExtender.callbacks.sendToIntruder(
                        service.getHost(), service.getPort(), 
                        service.getProtocol().equalsIgnoreCase("https"), 
                        targetMsg.getRequest()
                    );
                }
            }
        } catch (Exception ex) {
            BurpExtender.callbacks.printError("Failed to send to " + tool + ": " + ex.getMessage());
        }
    }

    private static String getCurlCommand(IHttpRequestResponse messageInfo, String urlStr) {
        if (messageInfo == null) {
            if (urlStr != null) {
                return "curl -i -s -k '" + urlStr.replace("'", "'\\''") + "'";
            }
            return null;
        }
        try {
            byte[] requestBytes = messageInfo.getRequest();
            if (requestBytes == null) {
                if (urlStr != null) {
                    return "curl -i -s -k '" + urlStr.replace("'", "'\\''") + "'";
                }
                return null;
            }
            IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(messageInfo);
            List<String> headers = reqInfo.getHeaders();
            if (headers == null || headers.isEmpty()) return null;
            
            StringBuilder curl = new StringBuilder("curl -i -s -k");
            // method & path
            String firstHeader = headers.get(0);
            String[] parts = firstHeader.split(" ");
            String method = parts.length > 0 ? parts[0] : "GET";
            curl.append(" -X ").append(method);
            
            // headers
            for (int i = 1; i < headers.size(); i++) {
                String h = headers.get(i);
                h = h.replace("'", "'\\''");
                curl.append(" -H '").append(h).append("'");
            }
            
            // body
            int bodyOffset = reqInfo.getBodyOffset();
            if (bodyOffset < requestBytes.length) {
                byte[] bodyBytes = Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length);
                String bodyStr = new String(bodyBytes, java.nio.charset.StandardCharsets.UTF_8);
                bodyStr = bodyStr.replace("'", "'\\''");
                curl.append(" --data-binary '").append(bodyStr).append("'");
            }
            
            String url = reqInfo.getUrl() != null ? reqInfo.getUrl().toString() : urlStr;
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

    private static class FallbackHttpRequestResponse implements IHttpRequestResponse {
        private final IHttpService service;
        private final byte[] request;

        public FallbackHttpRequestResponse(IHttpService service, byte[] request) {
            this.service = service;
            this.request = request;
        }

        @Override
        public byte[] getRequest() { return request; }

        @Override
        public void setRequest(byte[] message) {}

        @Override
        public byte[] getResponse() { return null; }

        @Override
        public void setResponse(byte[] message) {}

        @Override
        public String getComment() { return "ReconMaster Fallback"; }

        @Override
        public void setComment(String comment) {}

        @Override
        public String getHighlight() { return null; }

        @Override
        public void setHighlight(String color) {}

        @Override
        public IHttpService getHttpService() { return service; }

        @Override
        public void setHttpService(IHttpService httpService) {}
    }
}
