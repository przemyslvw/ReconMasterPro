package burp.modules;

import burp.*;
import burp.models.GraphQLEndpoint;
import burp.utils.GraphQLDetector;
import burp.utils.GraphQLSchemaParser;

import java.util.Map;
import java.util.concurrent.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public class GraphQLExtractor implements IHttpListener {

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
    public void processHttpMessage(int toolFlag, boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {
        executor.submit(() -> {
            try {
                IHttpService service = messageInfo.getHttpService();
                String host = service.getHost();
                String scheme = service.getProtocol();
                int port = service.getPort();

                IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(messageInfo);
                String path = reqInfo.getUrl().getPath();
                String portSuffix = (port == 80 || port == 443) ? "" : ":" + port;
                String url = scheme + "://" + host + portSuffix + path;

                String detectionMethod = null;

                if (messageIsRequest) {
                    // detekcja z żądania
                    byte[] req = messageInfo.getRequest();
                    int bodyOffset = reqInfo.getBodyOffset();
                    String body = new String(req, bodyOffset, req.length - bodyOffset, "UTF-8");

                    String contentType = reqInfo.getHeaders().stream()
                        .filter(h -> h.toLowerCase().startsWith("content-type:"))
                        .findFirst().orElse("").toLowerCase();

                    if (GraphQLDetector.isGraphQLPath(path)) {
                        detectionMethod = "path";
                    } else if (GraphQLDetector.isGraphQLContentType(contentType)) {
                        detectionMethod = "content-type";
                    } else if (GraphQLDetector.isGraphQLRequestBody(body)) {
                        detectionMethod = "request-body";
                    }

                } else {
                    // detekcja i parsowanie z odpowiedzi
                    byte[] response = messageInfo.getResponse();
                    if (response == null) return;

                    IResponseInfo respInfo = BurpExtender.helpers.analyzeResponse(response);
                    int bodyOffset = respInfo.getBodyOffset();
                    String body = new String(response, bodyOffset,
                        response.length - bodyOffset, "UTF-8");

                    if (GraphQLDetector.isGraphQLResponseBody(body)) {
                        detectionMethod = "response-body";

                        // jeśli to odpowiedź introspection — parsuj od razu
                        if (GraphQLDetector.isIntrospectionResponse(body)) {
                            String key = host + "|" + url;
                            GraphQLEndpoint ep = discovered.computeIfAbsent(key,
                                k -> {
                                    GraphQLEndpoint e = new GraphQLEndpoint(host, url, "response-body", messageInfo);
                                    onEndpointFound.accept(e);
                                    return e;
                                });

                            ep.introspectionEnabled = true;
                            GraphQLSchemaParser.ParsedSchema schema =
                                GraphQLSchemaParser.parse(body);
                            if (!schema.types.isEmpty()) {
                                ep.schemaLoaded = true;
                                onSchemaReady.accept(ep, schema);
                            }
                            return;
                        }
                    }
                }

                if (detectionMethod != null) {
                    String key = host + "|" + url;
                    final String finalMethod = detectionMethod;
                    discovered.computeIfAbsent(key, k -> {
                        GraphQLEndpoint ep = new GraphQLEndpoint(host, url, finalMethod, messageInfo);
                        onEndpointFound.accept(ep);
                        return ep;
                    });
                }

            } catch (Exception e) {
                try {
                    BurpExtender.callbacks.printError("GraphQLExtractor: " + e.getMessage());
                } catch (Exception ignored) {}
            }
        });
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

                byte[] body = introspectionQuery.getBytes("UTF-8");

                // buduj żądanie HTTP
                String host = endpoint.host;
                java.net.URL url = new java.net.URL(endpoint.url);
                int port = url.getPort();
                boolean useHttps = url.getProtocol().equalsIgnoreCase("https");
                if (port == -1) port = useHttps ? 443 : 80;

                IHttpService service = BurpExtender.helpers.buildHttpService(
                    host, port, useHttps);

                byte[] request = BurpExtender.helpers.buildHttpMessage(
                    java.util.List.of(
                        "POST " + url.getPath() + " HTTP/1.1",
                        "Host: " + host,
                        "Content-Type: application/json",
                        "Content-Length: " + body.length,
                        "Accept: application/json",
                        "User-Agent: Mozilla/5.0"
                    ),
                    body
                );

                IHttpRequestResponse responseInfo = BurpExtender.callbacks.makeHttpRequest(service, request);
                if (responseInfo == null) return;
                byte[] response = responseInfo.getResponse();

                IResponseInfo respInfo = BurpExtender.helpers.analyzeResponse(response);
                int bodyOffset = respInfo.getBodyOffset();
                String responseBody = new String(response, bodyOffset,
                    response.length - bodyOffset, "UTF-8");

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
                try {
                    BurpExtender.callbacks.printError(
                        "GraphQL introspection failed for " + endpoint.url + ": " + e.getMessage());
                } catch (Exception ignored) {}
            }
        });
    }

    public void shutdown() { executor.shutdownNow(); }
}
