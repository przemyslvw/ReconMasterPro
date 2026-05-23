package burp.modules;

import burp.utils.SettingsManager;
import burp.utils.AiProvider;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

public class AiClientTest {

    private HttpServer server;
    private int port;
    private Map<String, String> configStore;
    private MontoyaApi fakeApi;
    private SettingsManager settings;
    private AiClient client;

    // Tracker fields for mock server requests
    private volatile String lastRequestPath;
    private volatile String lastRequestBody;
    private volatile String lastAuthorizationHeader;
    private volatile String responseToReturn;
    private volatile int statusCodeToReturn;

    @BeforeEach
    void setUp() throws IOException {
        configStore = new HashMap<>();
        
        Preferences fakePreferences = (Preferences) Proxy.newProxyInstance(
            Preferences.class.getClassLoader(),
            new Class<?>[]{Preferences.class},
            (proxy, method, args) -> {
                if ("setString".equals(method.getName())) {
                    configStore.put((String) args[0], (String) args[1]);
                    return null;
                } else if ("getString".equals(method.getName())) {
                    return configStore.get((String) args[0]);
                }
                return null;
            }
        );

        Persistence fakePersistence = (Persistence) Proxy.newProxyInstance(
            Persistence.class.getClassLoader(),
            new Class<?>[]{Persistence.class},
            (proxy, method, args) -> {
                if ("preferences".equals(method.getName())) {
                    return fakePreferences;
                }
                return null;
            }
        );

        fakeApi = (MontoyaApi) Proxy.newProxyInstance(
            MontoyaApi.class.getClassLoader(),
            new Class<?>[]{MontoyaApi.class},
            (proxy, method, args) -> {
                if ("persistence".equals(method.getName())) {
                    return fakePersistence;
                }
                return null;
            }
        );

        settings = new SettingsManager(fakeApi);
        client = new AiClient(settings);

        // Start mock HTTP Server on random port
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();
        server.createContext("/", new MockHandler());
        server.start();

        // Configure client to use our mock server URL
        client.geminiBaseUrl = "http://127.0.0.1:" + port;
        client.deepseekBaseUrl = "http://127.0.0.1:" + port;

        lastRequestPath = null;
        lastRequestBody = null;
        lastAuthorizationHeader = null;
        responseToReturn = "{}";
        statusCodeToReturn = 200;
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private class MockHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            lastRequestPath = exchange.getRequestURI().toString();
            lastAuthorizationHeader = exchange.getRequestHeaders().getFirst("Authorization");

            InputStream is = exchange.getRequestBody();
            lastRequestBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);

            byte[] resp = responseToReturn.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCodeToReturn, resp.length > 0 ? resp.length : -1);
            if (resp.length > 0) {
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(resp);
                }
            }
            exchange.close();
        }
    }

    @Test
    void testGoogleGeminiSuccess() throws Exception {
        settings.setAiProvider(AiProvider.GOOGLE);
        settings.setAiGoogleKey("test-gemini-key");
        settings.setAiModel("gemini-1.5-flash");

        // Mock response
        responseToReturn = "{\n" +
                "  \"candidates\": [\n" +
                "    {\n" +
                "      \"content\": {\n" +
                "        \"parts\": [\n" +
                "          {\n" +
                "            \"text\": \"Hello from Gemini!\"\n" +
                "          }\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        String response = client.sendPrompt("You are a system prompt.", "Explain XSS.");

        assertEquals("Hello from Gemini!", response);
        assertNotNull(lastRequestPath);
        assertTrue(lastRequestPath.contains("/v1beta/models/gemini-1.5-flash:generateContent"));
        assertTrue(lastRequestPath.contains("key=test-gemini-key"));

        // Verify request body JSON structure
        JsonObject requestJson = JsonParser.parseString(lastRequestBody).getAsJsonObject();
        assertTrue(requestJson.has("contents"));
        assertTrue(requestJson.has("systemInstruction"));
    }

    @Test
    void testDeepSeekSuccess() throws Exception {
        settings.setAiProvider(AiProvider.DEEPSEEK);
        settings.setAiDeepSeekKey("test-deepseek-key");
        settings.setAiModel("deepseek-chat");

        responseToReturn = "{\n" +
                "  \"choices\": [\n" +
                "    {\n" +
                "      \"message\": {\n" +
                "        \"role\": \"assistant\",\n" +
                "        \"content\": \"Hello from DeepSeek!\"\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        String response = client.sendPrompt("System prompt.", "Explain SQLi.");

        assertEquals("Hello from DeepSeek!", response);
        assertEquals("/v1/chat/completions", lastRequestPath);
        assertEquals("Bearer test-deepseek-key", lastAuthorizationHeader);

        JsonObject requestJson = JsonParser.parseString(lastRequestBody).getAsJsonObject();
        assertEquals("deepseek-chat", requestJson.get("model").getAsString());
        assertTrue(requestJson.has("messages"));
    }

    @Test
    void testLocalApiSuccess() throws Exception {
        settings.setAiProvider(AiProvider.LOCAL);
        settings.setAiLocalUrl("http://127.0.0.1:" + port + "/v1");
        settings.setAiModel("llama3");

        responseToReturn = "{\n" +
                "  \"choices\": [\n" +
                "    {\n" +
                "      \"message\": {\n" +
                "        \"role\": \"assistant\",\n" +
                "        \"content\": \"Hello from local Ollama!\"\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        String response = client.sendPrompt("System prompt.", "Explain SSRF.");

        assertEquals("Hello from local Ollama!", response);
        assertEquals("/v1/chat/completions", lastRequestPath);

        JsonObject requestJson = JsonParser.parseString(lastRequestBody).getAsJsonObject();
        assertEquals("llama3", requestJson.get("model").getAsString());
    }

    @Test
    void testHttpErrorHandling() {
        settings.setAiProvider(AiProvider.DEEPSEEK);
        settings.setAiDeepSeekKey("bad-key");
        settings.setAiModel("deepseek-chat");

        statusCodeToReturn = 401;
        responseToReturn = "{\"error\": {\"message\": \"Invalid API Key provided\"}}";

        IOException exception = assertThrows(IOException.class, () -> {
            client.sendPrompt("Sys", "User");
        });

        assertTrue(exception.getMessage().contains("HTTP Error 401: Invalid API Key provided"));
    }

    @Test
    void testAsyncExecution() throws InterruptedException {
        settings.setAiProvider(AiProvider.LOCAL);
        settings.setAiLocalUrl("http://127.0.0.1:" + port + "/v1");
        settings.setAiModel("llama3");

        responseToReturn = "{\n" +
                "  \"choices\": [\n" +
                "    {\n" +
                "      \"message\": {\n" +
                "        \"content\": \"Async content\"\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> resultRef = new AtomicReference<>();
        AtomicReference<Throwable> errorRef = new AtomicReference<>();

        client.sendPromptAsync("System", "User", new AiClient.AiCallback() {
            @Override
            public void onSuccess(String response) {
                resultRef.set(response);
                latch.countDown();
            }

            @Override
            public void onFailure(Throwable t) {
                errorRef.set(t);
                latch.countDown();
            }
        });

        boolean completed = latch.await(5, TimeUnit.SECONDS);

        assertTrue(completed);
        assertNull(errorRef.get());
        assertEquals("Async content", resultRef.get());
    }
}
