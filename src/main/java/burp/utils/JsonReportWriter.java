package burp.utils;

import burp.models.ReportData;
import burp.models.Secret;
import com.google.gson.*;
import com.google.gson.stream.*;

import java.io.IOException;
import java.time.Instant;

public class JsonReportWriter {

    private static final Gson GSON = new GsonBuilder()
        .registerTypeAdapter(Instant.class, new InstantAdapter())
        .addSerializationExclusionStrategy(new ExcludeFullValue())
        .setPrettyPrinting()
        .serializeNulls()
        .create();

    public static String write(ReportData data) {
        return GSON.toJson(data);
    }

    private static class InstantAdapter extends TypeAdapter<Instant> {
        @Override
        public void write(JsonWriter out, Instant value) throws IOException {
            if (value == null) { out.nullValue(); return; }
            out.value(value.toString());
        }
        @Override
        public Instant read(JsonReader in) throws IOException {
            return Instant.parse(in.nextString());
        }
    }

    // wyklucza pole `fullValue` z Secret — nie trafia do raportu
    private static class ExcludeFullValue implements ExclusionStrategy {
        @Override
        public boolean shouldSkipField(FieldAttributes f) {
            return f.getDeclaringClass() == Secret.class
                && "fullValue".equals(f.getName());
        }
        @Override
        public boolean shouldSkipClass(Class<?> clazz) { return false; }
    }
}
