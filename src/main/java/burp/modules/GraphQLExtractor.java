package burp.modules;

import burp.ReconMasterPro;
import burp.models.GraphQLEndpoint;
import burp.utils.GraphQLDetector;
import burp.utils.GraphQLSchemaParser;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ToolType;

import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public class GraphQLExtractor implements HttpHandler {

    // klucz: host|url → endpoint (deduplikacja)
    private final Map<String, GraphQLEndpoint> discovered = new ConcurrentHashMap<>();

    private final Consumer<GraphQLEndpoint> onEndpointFound;
    private final BiConsumer<GraphQLEndpoint, GraphQLSchemaParser.ParsedSchema> onSchemaReady;

    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ReconMaster-GraphQL");
        t.setDaemon(true);
        return t;
    });

    public GraphQLExtractor(
            Consumer<GraphQLEndpoint> onEndpointFound,
            BiConsumer<GraphQLEndpoint, GraphQLSchemaParser.ParsedSchema> onSchemaReady) {
        this.onEndpointFound = onEndpointFound;
        this.onSchemaReady = onSchemaReady;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (requestToBeSent.toolSource().isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.INTRUDER, ToolType.SCANNER)) {
            executor.submit(() -> processRequest(requestToBeSent));
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (responseReceived.toolSource().isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.INTRUDER, ToolType.SCANNER)) {
            executor.submit(() -> processResponse(responseReceived));
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void processRequest(HttpRequestToBeSent request) {
        try {
            String host = request.httpService().host();
            String path = request.path();
            String url = request.url();

            String body = request.bodyToString();
            List<String> headers = request.headers().stream().map(h -> h.toString()).toList();
            String contentType = getContentType(headers);

            String detectionMethod = null;
            if (GraphQLDetector.isGraphQLPath(path)) {
                detectionMethod = "path";
            } else if (GraphQLDetector.isGraphQLContentType(contentType)) {
                detectionMethod = "content-type";
            } else if (GraphQLDetector.isGraphQLRequestBody(body)) {
                detectionMethod = "request-body";
            }

            if (detectionMethod != null) {
                String key = host + "|" + url;
                final String finalMethod = detectionMethod;
                discovered.computeIfAbsent(key, k -> {
                    HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(request, null);
                    GraphQLEndpoint ep = new GraphQLEndpoint(host, url, finalMethod, reqResp);
                    onEndpointFound.accept(ep);
                    return ep;
                });
            }
        } catch (Exception e) {
            logError("processRequest error: " + e.getMessage());
        }
    }

    private void processResponse(HttpResponseReceived response) {
        try {
            HttpRequest request = response.initiatingRequest();
            if (request == null) return;

            String host = request.httpService().host();
            String url = request.url();

            String body = response.bodyToString();
            if (body == null || body.isBlank()) return;

            if (GraphQLDetector.isGraphQLResponseBody(body)) {
                HttpRequestResponse reqResp = HttpRequestResponse.httpRequestResponse(request, response);

                if (GraphQLDetector.isIntrospectionResponse(body)) {
                    String key = host + "|" + url;
                    GraphQLEndpoint ep = discovered.computeIfAbsent(key, k -> {
                        GraphQLEndpoint e = new GraphQLEndpoint(host, url, "response-body", reqResp);
                        onEndpointFound.accept(e);
                        return e;
                    });

                    ep.introspectionEnabled = true;
                    GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(body);
                    if (!schema.types.isEmpty()) {
                        ep.schemaLoaded = true;
                        onSchemaReady.accept(ep, schema);
                    }
                    return;
                }

                String key = host + "|" + url;
                discovered.computeIfAbsent(key, k -> {
                    GraphQLEndpoint ep = new GraphQLEndpoint(host, url, "response-body", reqResp);
                    onEndpointFound.accept(ep);
                    return ep;
                });
            }
        } catch (Exception e) {
            logError("processResponse error: " + e.getMessage());
        }
    }

    /**
     * Aktywne zapytanie introspection — wywoływane przez UI po kliknięciu przycisku.
     * Wysyła standardowe zapytanie do wskazanego endpointu i parsuje odpowiedź.
     */
    public void runIntrospection(GraphQLEndpoint endpoint) {
        executor.submit(() -> {
            try {
                String introspectionQuery =
                    "{\"query\":\"{__schema{queryType{name}mutationType{name}" +
                    "subscriptionType{name}types{kind name description fields{name description " +
                    "type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}\"}";

                // buduj żądanie HTTP
                java.net.URL url = new java.net.URL(endpoint.url);
                int port = url.getPort();
                boolean useHttps = url.getProtocol().equalsIgnoreCase("https");
                if (port == -1) port = useHttps ? 443 : 80;

                burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(
                    endpoint.host, port, useHttps);

                HttpRequest request = HttpRequest.httpRequest()
                    .withService(service)
                    .withMethod("POST")
                    .withPath(url.getPath())
                    .withHeader("Host", endpoint.host)
                    .withHeader("Content-Type", "application/json")
                    .withHeader("Accept", "application/json")
                    .withHeader("User-Agent", "Mozilla/5.0")
                    .withBody(introspectionQuery);

                HttpRequestResponse responseInfo = ReconMasterPro.api.http().sendRequest(request);
                if (responseInfo == null || responseInfo.response() == null) return;

                String responseBody = responseInfo.response().bodyToString();

                if (GraphQLDetector.isIntrospectionResponse(responseBody)) {
                    endpoint.introspectionEnabled = true;
                    GraphQLSchemaParser.ParsedSchema schema =
                        GraphQLSchemaParser.parse(responseBody);
                    if (!schema.types.isEmpty()) {
                        endpoint.schemaLoaded = true;
                        onSchemaReady.accept(endpoint, schema);
                    }
                } else {
                    // introspection wyłączone lub odpowiedź błędu
                    endpoint.introspectionEnabled = false;
                    onSchemaReady.accept(endpoint, new GraphQLSchemaParser.ParsedSchema());
                }

            } catch (Exception e) {
                logError("GraphQL introspection failed for " + endpoint.url + ": " + e.getMessage());
            }
        });
    }

    private String getContentType(List<String> headers) {
        return headers.stream()
            .filter(h -> h.toLowerCase().startsWith("content-type:"))
            .findFirst()
            .orElse("")
            .toLowerCase();
    }

    public void shutdown() { executor.shutdownNow(); }

    private void logError(String msg) {
        if (ReconMasterPro.api != null) {
            ReconMasterPro.api.logging().logToError("GraphQL error: " + msg);
        } else {
            System.err.println("GraphQL error: " + msg);
        }
    }
}
