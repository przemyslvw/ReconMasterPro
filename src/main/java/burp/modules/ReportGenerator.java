package burp.modules;

import burp.models.*;
import burp.utils.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.function.Supplier;

public class ReportGenerator {

    private final Supplier<List<Endpoint>>        endpointSupplier;
    private final Supplier<List<Technology>>      techSupplier;
    private final Supplier<List<Secret>>          secretSupplier;
    private final Supplier<List<CorsFinding>>     corsSupplier;
    private final Supplier<List<CloudAsset>>      cloudSupplier;
    private final Supplier<List<GraphQLEndpoint>> graphqlSupplier;

    public ReportGenerator(
            Supplier<List<Endpoint>>        endpointSupplier,
            Supplier<List<Technology>>      techSupplier,
            Supplier<List<Secret>>          secretSupplier,
            Supplier<List<CorsFinding>>     corsSupplier,
            Supplier<List<CloudAsset>>      cloudSupplier,
            Supplier<List<GraphQLEndpoint>> graphqlSupplier) {
        this.endpointSupplier = endpointSupplier;
        this.techSupplier     = techSupplier;
        this.secretSupplier   = secretSupplier;
        this.corsSupplier     = corsSupplier;
        this.cloudSupplier    = cloudSupplier;
        this.graphqlSupplier  = graphqlSupplier;
    }

    public enum Format { JSON, CSV, MARKDOWN, HTML }

    public void export(Format format, String targetHost, File outputFile) throws IOException {
        ReportData data = new ReportData(
            targetHost,
            endpointSupplier.get(),
            techSupplier.get(),
            secretSupplier.get(),
            corsSupplier.get(),
            cloudSupplier.get(),
            graphqlSupplier.get()
        );

        switch (format) {
            case JSON     -> writeText(JsonReportWriter.write(data), outputFile);
            case MARKDOWN -> writeText(MarkdownReportWriter.write(data), outputFile);
            case HTML     -> writeText(HtmlReportWriter.write(data), outputFile);
            case CSV      -> Files.write(outputFile.toPath(), CsvReportWriter.writeZip(data));
        }
    }

    private void writeText(String content, File file) throws IOException {
        try (Writer w = new OutputStreamWriter(
                new FileOutputStream(file), StandardCharsets.UTF_8)) {
            w.write(content);
        }
    }

    public ReportData snapshot(String targetHost) {
        return new ReportData(targetHost,
            endpointSupplier.get(), techSupplier.get(),
            secretSupplier.get(), corsSupplier.get(),
            cloudSupplier.get(), graphqlSupplier.get());
    }
}
