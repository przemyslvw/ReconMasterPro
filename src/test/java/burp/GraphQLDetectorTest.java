package burp;

import burp.utils.GraphQLDetector;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GraphQLDetectorTest {

    // ── Detekcja po URL-u ─────────────────────────────────────────────

    @Test
    void detectsStandardGraphqlPath() {
        assertTrue(GraphQLDetector.isGraphQLPath("/graphql"));
    }

    @Test
    void detectsApiGraphqlPath() {
        assertTrue(GraphQLDetector.isGraphQLPath("/api/graphql"));
    }

    @Test
    void detectsVersionedPath() {
        assertTrue(GraphQLDetector.isGraphQLPath("/graphql/v1"));
        assertTrue(GraphQLDetector.isGraphQLPath("/v2/graphql"));
    }

    @Test
    void detectsAltPaths() {
        assertTrue(GraphQLDetector.isGraphQLPath("/gql"));
        assertTrue(GraphQLDetector.isGraphQLPath("/query"));
        assertTrue(GraphQLDetector.isGraphQLPath("/graphiql"));
    }

    @Test
    void nonGraphqlPathReturnsFalse() {
        assertFalse(GraphQLDetector.isGraphQLPath("/api/users"));
        assertFalse(GraphQLDetector.isGraphQLPath("/login"));
        assertFalse(GraphQLDetector.isGraphQLPath("/"));
    }

    // ── Detekcja z body żądania ───────────────────────────────────────

    @Test
    void detectsGraphQLQueryInRequestBody() {
        String body = "{\"query\":\"{ users { id name } }\"}";
        assertTrue(GraphQLDetector.isGraphQLRequestBody(body));
    }

    @Test
    void detectsGraphQLMutationInRequestBody() {
        String body = "{\"query\":\"mutation { createUser(name: \\\"test\\\") { id } }\"}";
        assertTrue(GraphQLDetector.isGraphQLRequestBody(body));
    }

    @Test
    void detectsIntrospectionInRequestBody() {
        String body = "{\"query\":\"{__schema{queryType{name}}}\"}";
        assertTrue(GraphQLDetector.isGraphQLRequestBody(body));
    }

    @Test
    void regularJsonBodyReturnsFalse() {
        String body = "{\"username\":\"admin\",\"password\":\"123\"}";
        assertFalse(GraphQLDetector.isGraphQLRequestBody(body));
    }

    // ── Detekcja z body odpowiedzi ────────────────────────────────────

    @Test
    void detectsGraphQLDataResponse() {
        String body = "{\"data\":{\"users\":[{\"id\":1}]}}";
        assertTrue(GraphQLDetector.isGraphQLResponseBody(body));
    }

    @Test
    void detectsGraphQLErrorsResponse() {
        String body = "{\"errors\":[{\"message\":\"Not authenticated\",\"locations\":[]}]}";
        assertTrue(GraphQLDetector.isGraphQLResponseBody(body));
    }

    @Test
    void detectsIntrospectionResponse() {
        String body = "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}}";
        assertTrue(GraphQLDetector.isGraphQLResponseBody(body));
    }

    @Test
    void detectsTypenameInResponse() {
        String body = "{\"data\":{\"user\":{\"__typename\":\"User\",\"id\":1}}}";
        assertTrue(GraphQLDetector.isGraphQLResponseBody(body));
    }

    @Test
    void regularJsonResponseReturnsFalse() {
        String body = "{\"status\":\"ok\",\"count\":42}";
        assertFalse(GraphQLDetector.isGraphQLResponseBody(body));
    }

    // ── Detekcja z nagłówka Content-Type ─────────────────────────────

    @Test
    void detectsGraphQLContentType() {
        assertTrue(GraphQLDetector.isGraphQLContentType("application/graphql"));
    }

    @Test
    void jsonContentTypeReturnsFalse() {
        assertFalse(GraphQLDetector.isGraphQLContentType("application/json"));
    }

    // ── Detekcja endpointu introspection ─────────────────────────────

    @Test
    void detectsIntrospectionEnabled() {
        String body = "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}," +
                      "\"types\":[{\"name\":\"Query\",\"kind\":\"OBJECT\"}]}}}";
        assertTrue(GraphQLDetector.isIntrospectionResponse(body));
    }

    @Test
    void regularDataResponseIsNotIntrospection() {
        String body = "{\"data\":{\"users\":[{\"id\":1}]}}";
        assertFalse(GraphQLDetector.isIntrospectionResponse(body));
    }
}
