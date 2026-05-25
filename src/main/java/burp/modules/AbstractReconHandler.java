package burp.modules;

import burp.ReconMasterPro;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * Base class for ReconMaster passive HTTP handlers. Provides the shared
 * executor, tool-source filter, content-type extraction, and logging
 * boilerplate so each module focuses only on its analysis logic.
 */
public abstract class AbstractReconHandler implements HttpHandler {

    protected final ExecutorService executor;
    protected final String moduleName;

    protected AbstractReconHandler(String moduleName) {
        this(moduleName, 1);
    }

    protected AbstractReconHandler(String moduleName, int threads) {
        this.moduleName = moduleName;
        ThreadFactory factory = r -> {
            Thread t = new Thread(r, "ReconMaster-" + moduleName);
            t.setDaemon(true);
            return t;
        };
        this.executor = threads <= 1
            ? Executors.newSingleThreadExecutor(factory)
            : Executors.newFixedThreadPool(threads, factory);
    }

    protected static boolean isFromAuditableSource(ToolSource src) {
        return src.isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.INTRUDER, ToolType.SCANNER);
    }

    protected static String getContentType(List<HttpHeader> headers) {
        for (HttpHeader h : headers) {
            if ("content-type".equalsIgnoreCase(h.name())) {
                return h.value().toLowerCase();
            }
        }
        return "";
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        return ResponseReceivedAction.continueWith(response);
    }

    protected void log(String msg) {
        if (ReconMasterPro.api != null) {
            ReconMasterPro.api.logging().logToOutput("[" + moduleName + "] " + msg);
        } else {
            System.out.println("[" + moduleName + "] " + msg);
        }
    }

    protected void logError(String msg) {
        if (ReconMasterPro.api != null) {
            ReconMasterPro.api.logging().logToError("[" + moduleName + "] " + msg);
        } else {
            System.err.println("[" + moduleName + "] " + msg);
        }
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
