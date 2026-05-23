package burp.utils;

import java.util.List;
import java.util.regex.Pattern;

public class GraphQLDetector {

    private static final List<String> GQL_PATHS = List.of(
        "/graphql", "/gql", "/graphiql", "/query",
        "/api/graphql", "/graph", "/playground"
    );

    private static final Pattern GQL_PATH_RE = Pattern.compile(
        "(?i)(/graphql|/gql|/graphiql|/playground|/query)(/|\\?|$|/v\\d)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern GQL_REQUEST_RE = Pattern.compile(
        "\"query\"\\s*:\\s*\"\\s*(query|mutation|subscription|\\{|\\{\\s*__)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern GQL_RESPONSE_RE = Pattern.compile(
        "\"(data|errors)\"\\s*:\\s*[{\\[]",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern INTROSPECTION_RE = Pattern.compile(
        "\"__schema\"\\s*:\\s*\\{",
        Pattern.CASE_INSENSITIVE
    );

    public static boolean isGraphQLPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase();

        for (String gqlPath : GQL_PATHS) {
            if (lower.equals(gqlPath) ||
                lower.startsWith(gqlPath + "/") ||
                lower.startsWith(gqlPath + "?")) {
                return true;
            }
        }
        // /v1/graphql, /graphql/v2, etc.
        return GQL_PATH_RE.matcher(path).find();
    }

    public static boolean isGraphQLRequestBody(String body) {
        if (body == null || body.isBlank()) return false;
        return GQL_REQUEST_RE.matcher(body).find();
    }

    public static boolean isGraphQLResponseBody(String body) {
        if (body == null || body.isBlank()) return false;
        if (!GQL_RESPONSE_RE.matcher(body).find()) return false;

        // odrzuć proste REST odpowiedzi — GQL ma "data" z obiektem lub "errors" z tablicą
        // heurystyka: jeśli zawiera "data":{ lub "errors":[ — prawdopodobnie GraphQL
        return body.contains("\"data\":{") ||
               body.contains("\"data\": {") ||
               body.contains("\"errors\":[") ||
               body.contains("\"errors\": [") ||
               body.contains("__typename");
    }

    public static boolean isGraphQLContentType(String contentType) {
        return contentType != null &&
               contentType.toLowerCase().contains("application/graphql");
    }

    public static boolean isIntrospectionResponse(String body) {
        if (body == null) return false;
        return INTROSPECTION_RE.matcher(body).find() && body.contains("\"queryType\"");
    }
}
