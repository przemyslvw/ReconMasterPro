package burp.modules;

import burp.utils.SettingsManager;
import burp.utils.AiProvider;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public class AiClient {

    private final SettingsManager settings;
    private final HttpClient httpClient;

    // Package-private to allow mock server override in tests
    String geminiBaseUrl = "https://generativelanguage.googleapis.com";
    String deepseekBaseUrl = "https://api.deepseek.com";

    public interface AiCallback {
        void onSuccess(String response);
        void onFailure(Throwable t);
    }

    public AiClient(SettingsManager settings) {
        this.settings = settings;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    /**
     * Sends the prompts to the selected AI provider synchronously.
     */
    public String sendPrompt(String systemPrompt, String userPrompt) throws Exception {
        AiProvider provider = settings.getAiProvider();
        switch (provider) {
            case GOOGLE:
                return sendGoogleGemini(systemPrompt, userPrompt);
            case DEEPSEEK:
                return sendDeepSeek(systemPrompt, userPrompt);
            case LOCAL:
                return sendLocalApi(systemPrompt, userPrompt);
            default:
                throw new IllegalStateException("Unknown AI provider: " + provider);
        }
    }

    /**
     * Sends the prompts to the selected AI provider asynchronously.
     */
    public void sendPromptAsync(String systemPrompt, String userPrompt, AiCallback callback) {
        new Thread(() -> {
            try {
                String response = sendPrompt(systemPrompt, userPrompt);
                callback.onSuccess(response);
            } catch (Throwable t) {
                logError("Failed to communicate with AI API", t);
                callback.onFailure(t);
            }
        }).start();
    }

    private String sendGoogleGemini(String systemPrompt, String userPrompt) throws Exception {
        String key = settings.getAiGoogleKey();
        if (key == null || key.trim().isEmpty()) {
            throw new IllegalArgumentException("Google Gemini API Key is not configured");
        }
        String model = settings.getAiModel();
        String url = geminiBaseUrl + "/v1beta/models/" + model + ":generateContent?key=" + key;

        JsonObject requestJson = new JsonObject();
        JsonArray contents = new JsonArray();
        JsonObject contentObj = new JsonObject();
        JsonArray parts = new JsonArray();
        JsonObject partObj = new JsonObject();
        partObj.addProperty("text", userPrompt);
        parts.add(partObj);
        contentObj.add("parts", parts);
        contents.add(contentObj);
        requestJson.add("contents", contents);

        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject sysInstObj = new JsonObject();
            JsonArray sysParts = new JsonArray();
            JsonObject sysPartObj = new JsonObject();
            sysPartObj.addProperty("text", systemPrompt);
            sysParts.add(sysPartObj);
            sysInstObj.add("parts", sysParts);
            requestJson.add("systemInstruction", sysInstObj);
        }

        String requestBody = new Gson().toJson(requestJson);
        String responseBody = sendPostRequest(url, requestBody, null);

        JsonObject responseJson = JsonParser.parseString(responseBody).getAsJsonObject();
        JsonArray candidates = responseJson.getAsJsonArray("candidates");
        if (candidates == null || candidates.size() == 0) {
            throw new IOException("No candidates returned from Gemini API");
        }
        JsonObject firstCandidate = candidates.get(0).getAsJsonObject();
        JsonObject content = firstCandidate.getAsJsonObject("content");
        if (content == null) {
            throw new IOException("No content in Gemini response candidate");
        }
        JsonArray resParts = content.getAsJsonArray("parts");
        if (resParts == null || resParts.size() == 0) {
            throw new IOException("No parts returned in Gemini response candidate content");
        }
        return resParts.get(0).getAsJsonObject().get("text").getAsString();
    }

    private String sendDeepSeek(String systemPrompt, String userPrompt) throws Exception {
        String key = settings.getAiDeepSeekKey();
        if (key == null || key.trim().isEmpty()) {
            throw new IllegalArgumentException("DeepSeek API Key is not configured");
        }
        String url = deepseekBaseUrl + "/v1/chat/completions";

        JsonObject requestJson = new JsonObject();
        requestJson.addProperty("model", settings.getAiModel());

        JsonArray messages = new JsonArray();
        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject sysMsg = new JsonObject();
            sysMsg.addProperty("role", "system");
            sysMsg.addProperty("content", systemPrompt);
            messages.add(sysMsg);
        }
        JsonObject userMsg = new JsonObject();
        userMsg.addProperty("role", "user");
        userMsg.addProperty("content", userPrompt);
        messages.add(userMsg);
        requestJson.add("messages", messages);

        String requestBody = new Gson().toJson(requestJson);

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + key);

        String responseBody = sendPostRequest(url, requestBody, headers);

        JsonObject responseJson = JsonParser.parseString(responseBody).getAsJsonObject();
        JsonArray choices = responseJson.getAsJsonArray("choices");
        if (choices == null || choices.size() == 0) {
            throw new IOException("No choices returned from DeepSeek API");
        }
        JsonObject choice = choices.get(0).getAsJsonObject();
        JsonObject message = choice.getAsJsonObject("message");
        if (message == null || !message.has("content")) {
            throw new IOException("No content in DeepSeek response choice");
        }
        return message.get("content").getAsString();
    }

    private String sendLocalApi(String systemPrompt, String userPrompt) throws Exception {
        String localUrl = settings.getAiLocalUrl();
        if (localUrl == null || localUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Local API URL is not configured");
        }
        if (!localUrl.endsWith("/chat/completions") && !localUrl.endsWith("/completions")) {
            if (localUrl.endsWith("/")) {
                localUrl += "chat/completions";
            } else {
                localUrl += "/chat/completions";
            }
        }

        JsonObject requestJson = new JsonObject();
        requestJson.addProperty("model", settings.getAiModel());

        JsonArray messages = new JsonArray();
        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject sysMsg = new JsonObject();
            sysMsg.addProperty("role", "system");
            sysMsg.addProperty("content", systemPrompt);
            messages.add(sysMsg);
        }
        JsonObject userMsg = new JsonObject();
        userMsg.addProperty("role", "user");
        userMsg.addProperty("content", userPrompt);
        messages.add(userMsg);
        requestJson.add("messages", messages);

        String requestBody = new Gson().toJson(requestJson);
        String responseBody = sendPostRequest(localUrl, requestBody, null);

        JsonObject responseJson = JsonParser.parseString(responseBody).getAsJsonObject();
        JsonArray choices = responseJson.getAsJsonArray("choices");
        if (choices == null || choices.size() == 0) {
            throw new IOException("No choices returned from Local API");
        }
        JsonObject choice = choices.get(0).getAsJsonObject();
        JsonObject message = choice.getAsJsonObject("message");
        if (message == null || !message.has("content")) {
            throw new IOException("No content in Local API response choice");
        }
        return message.get("content").getAsString();
    }

    private String sendPostRequest(String url, String requestBody, Map<String, String> headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(90))
                .header("Content-Type", "application/json");

        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                builder.header(entry.getKey(), entry.getValue());
            }
        }

        HttpRequest request = builder
                .POST(HttpRequest.BodyPublishers.ofString(requestBody, java.nio.charset.StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        int statusCode = response.statusCode();
        String responseBody = response.body();

        if (statusCode < 200 || statusCode >= 300) {
            String errorDetails = "";
            try {
                JsonObject errorJson = JsonParser.parseString(responseBody).getAsJsonObject();
                if (errorJson.has("error")) {
                    JsonObject err = errorJson.getAsJsonObject("error");
                    if (err.has("message")) {
                        errorDetails = ": " + err.get("message").getAsString();
                    }
                }
            } catch (Exception ignored) {}

            throw new IOException("HTTP Error " + statusCode + errorDetails);
        }

        return responseBody;
    }

    private void logError(String message, Throwable t) {
        System.err.println("[AiClient Error] " + message + (t != null ? ": " + t.getMessage() : ""));
    }
}
