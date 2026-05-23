package burp;

import burp.models.GraphQLField;
import burp.models.GraphQLType;
import burp.utils.GraphQLSchemaParser;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class GraphQLSchemaParserTest {

    // minimalna odpowiedź introspection — Query z jednym polem
    private static final String MINIMAL_INTROSPECTION = 
        "{\n" +
        "  \"data\": {\n" +
        "    \"__schema\": {\n" +
        "      \"queryType\": { \"name\": \"Query\" },\n" +
        "      \"mutationType\": { \"name\": \"Mutation\" },\n" +
        "      \"subscriptionType\": null,\n" +
        "      \"types\": [\n" +
        "        {\n" +
        "          \"kind\": \"OBJECT\",\n" +
        "          \"name\": \"Query\",\n" +
        "          \"description\": null,\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"name\": \"user\",\n" +
        "              \"description\": \"Get a user by ID\",\n" +
        "              \"type\": {\n" +
        "                \"kind\": \"OBJECT\",\n" +
        "                \"name\": \"User\",\n" +
        "                \"ofType\": null\n" +
        "              }\n" +
        "            },\n" +
        "            {\n" +
        "              \"name\": \"users\",\n" +
        "              \"description\": null,\n" +
        "              \"type\": {\n" +
        "                \"kind\": \"LIST\",\n" +
        "                \"name\": null,\n" +
        "                \"ofType\": { \"kind\": \"OBJECT\", \"name\": \"User\", \"ofType\": null }\n" +
        "              }\n" +
        "            }\n" +
        "          ]\n" +
        "        },\n" +
        "        {\n" +
        "          \"kind\": \"OBJECT\",\n" +
        "          \"name\": \"Mutation\",\n" +
        "          \"description\": null,\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"name\": \"createUser\",\n" +
        "              \"description\": null,\n" +
        "              \"type\": {\n" +
        "                \"kind\": \"NON_NULL\",\n" +
        "                \"name\": null,\n" +
        "                \"ofType\": { \"kind\": \"OBJECT\", \"name\": \"User\", \"ofType\": null }\n" +
        "              }\n" +
        "            }\n" +
        "          ]\n" +
        "        },\n" +
        "        {\n" +
        "          \"kind\": \"OBJECT\",\n" +
        "          \"name\": \"User\",\n" +
        "          \"description\": \"Application user\",\n" +
        "          \"fields\": [\n" +
        "            {\n" +
        "              \"name\": \"id\",\n" +
        "              \"description\": null,\n" +
        "              \"type\": { \"kind\": \"NON_NULL\", \"name\": null,\n" +
        "                        \"ofType\": { \"kind\": \"SCALAR\", \"name\": \"ID\", \"ofType\": null } }\n" +
        "            },\n" +
        "            {\n" +
        "              \"name\": \"email\",\n" +
        "              \"description\": null,\n" +
        "              \"type\": { \"kind\": \"SCALAR\", \"name\": \"String\", \"ofType\": null }\n" +
        "            }\n" +
        "          ]\n" +
        "        },\n" +
        "        {\n" +
        "          \"kind\": \"SCALAR\",\n" +
        "          \"name\": \"String\",\n" +
        "          \"description\": null,\n" +
        "          \"fields\": null\n" +
        "        },\n" +
        "        {\n" +
        "          \"kind\": \"SCALAR\",\n" +
        "          \"name\": \"__Schema\",\n" +
        "          \"description\": \"built-in\",\n" +
        "          \"fields\": null\n" +
        "        }\n" +
        "      ]\n" +
        "    }\n" +
        "  }\n" +
        "}";

    @Test
    void parsesQueryTypeName() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        assertEquals("Query", schema.queryTypeName);
    }

    @Test
    void parsesMutationTypeName() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        assertEquals("Mutation", schema.mutationTypeName);
    }

    @Test
    void subscriptionTypeNullWhenNotDefined() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        assertNull(schema.subscriptionTypeName);
    }

    @Test
    void findsQueryType() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        GraphQLType query = schema.getType("Query");
        assertNotNull(query);
        assertEquals("OBJECT", query.kind);
    }

    @Test
    void queryTypeHasCorrectFieldCount() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        GraphQLType query = schema.getType("Query");
        assertEquals(2, query.fields.size());
    }

    @Test
    void queryFieldNamesCorrect() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        List<String> names = schema.getType("Query").fields.stream()
            .map(f -> f.name).toList();
        assertTrue(names.contains("user"));
        assertTrue(names.contains("users"));
    }

    @Test
    void listTypeFieldDetectedCorrectly() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        GraphQLField users = schema.getType("Query").fields.stream()
            .filter(f -> f.name.equals("users")).findFirst().orElse(null);
        assertNotNull(users);
        assertTrue(users.isList);
        assertEquals("User", users.typeName);
    }

    @Test
    void nonNullTypeFieldDetectedCorrectly() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        GraphQLField createUser = schema.getType("Mutation").fields.stream()
            .filter(f -> f.name.equals("createUser")).findFirst().orElse(null);
        assertNotNull(createUser);
        assertTrue(createUser.isNonNull);
        assertEquals("User", createUser.typeName);
    }

    @Test
    void userTypeHasCorrectFields() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        GraphQLType user = schema.getType("User");
        assertNotNull(user);
        assertEquals(2, user.fields.size());
    }

    @Test
    void scalarTypeIncluded() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        GraphQLType str = schema.getType("String");
        assertNotNull(str);
        assertEquals("SCALAR", str.kind);
    }

    @Test
    void builtInTypesFilteredOut() {
        // typy zaczynające się od __ są wewnętrzne GraphQL — nie powinny być w schemie
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(MINIMAL_INTROSPECTION);
        assertTrue(schema.types.stream().noneMatch(t -> t.name.startsWith("__")));
    }

    @Test
    void typeSignatureFormattedCorrectly() {
        GraphQLField nonNullList = new GraphQLField("items", "Product", true, true);
        assertEquals("[Product]!", nonNullList.typeSignature());

        GraphQLField nullable = new GraphQLField("name", "String", false, false);
        assertEquals("String", nullable.typeSignature());

        GraphQLField nonNullScalar = new GraphQLField("id", "ID", true, false);
        assertEquals("ID!", nonNullScalar.typeSignature());
    }

    @Test
    void returnsEmptySchemaOnNullInput() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse(null);
        assertNotNull(schema);
        assertTrue(schema.types.isEmpty());
    }

    @Test
    void returnsEmptySchemaOnMalformedJson() {
        GraphQLSchemaParser.ParsedSchema schema = GraphQLSchemaParser.parse("{not valid json}}");
        assertNotNull(schema);
        assertTrue(schema.types.isEmpty());
    }
}
