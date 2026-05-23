package burp.utils;

import burp.models.GraphQLField;
import burp.models.GraphQLType;
import com.google.gson.*;

import java.util.ArrayList;
import java.util.List;

public class GraphQLSchemaParser {

    public static class ParsedSchema {
        public String queryTypeName;
        public String mutationTypeName;
        public String subscriptionTypeName;
        public List<GraphQLType> types = new ArrayList<>();

        public GraphQLType getType(String name) {
            return types.stream().filter(t -> t.name.equals(name)).findFirst().orElse(null);
        }
    }

    public static ParsedSchema parse(String introspectionJson) {
        ParsedSchema result = new ParsedSchema();
        if (introspectionJson == null || introspectionJson.isBlank()) return result;

        try {
            JsonObject root = JsonParser.parseString(introspectionJson).getAsJsonObject();
            JsonObject schema = root
                .getAsJsonObject("data")
                .getAsJsonObject("__schema");

            result.queryTypeName        = extractTypeName(schema, "queryType");
            result.mutationTypeName     = extractTypeName(schema, "mutationType");
            result.subscriptionTypeName = extractTypeName(schema, "subscriptionType");

            JsonArray rawTypes = schema.getAsJsonArray("types");
            for (JsonElement el : rawTypes) {
                JsonObject rawType = el.getAsJsonObject();
                String name = getString(rawType, "name");
                String kind = getString(rawType, "kind");

                // pomiń wewnętrzne typy GraphQL
                if (name == null || name.startsWith("__")) continue;

                GraphQLType type = new GraphQLType(name, kind != null ? kind : "UNKNOWN");
                type.description = getString(rawType, "description");

                JsonElement fieldsEl = rawType.get("fields");
                if (fieldsEl != null && !fieldsEl.isJsonNull()) {
                    for (JsonElement fieldEl : fieldsEl.getAsJsonArray()) {
                        JsonObject rawField = fieldEl.getAsJsonObject();
                        GraphQLField field = parseField(rawField);
                        if (field != null) type.fields.add(field);
                    }
                }
                result.types.add(type);
            }

        } catch (Exception e) {
            // malformed JSON lub nieoczekiwana struktura — zwracamy pusty schemat
        }
        return result;
    }

    private static GraphQLField parseField(JsonObject rawField) {
        String name = getString(rawField, "name");
        if (name == null) return null;

        JsonObject typeRef = rawField.getAsJsonObject("type");
        String typeName = null;
        boolean isNonNull = false;
        boolean isList = false;

        // unwrap NON_NULL i LIST wrapperów
        while (typeRef != null) {
            String kind = getString(typeRef, "kind");
            if ("NON_NULL".equals(kind)) {
                isNonNull = true;
                typeRef = getNestedObject(typeRef, "ofType");
            } else if ("LIST".equals(kind)) {
                isList = true;
                typeRef = getNestedObject(typeRef, "ofType");
            } else {
                typeName = getString(typeRef, "name");
                break;
            }
        }

        return new GraphQLField(name, typeName != null ? typeName : "Unknown", isNonNull, isList);
    }

    private static String extractTypeName(JsonObject schema, String key) {
        JsonElement el = schema.get(key);
        if (el == null || el.isJsonNull()) return null;
        JsonObject obj = el.getAsJsonObject();
        return getString(obj, "name");
    }

    private static String getString(JsonObject obj, String key) {
        JsonElement el = obj.get(key);
        return (el == null || el.isJsonNull()) ? null : el.getAsString();
    }

    private static JsonObject getNestedObject(JsonObject obj, String key) {
        JsonElement el = obj.get(key);
        return (el == null || el.isJsonNull()) ? null : el.getAsJsonObject();
    }
}
