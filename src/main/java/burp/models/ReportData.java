package burp.models;

import java.time.Instant;
import java.util.List;

public class ReportData {
    public final String targetHost;
    public final Instant generatedAt;
    public final List<Endpoint>        endpoints;
    public final List<Technology>      technologies;
    public final List<Secret>          secrets;
    public final List<CorsFinding>     corsFindings;
    public final List<CloudAsset>      cloudAssets;
    public final List<GraphQLEndpoint> graphqlEndpoints;

    public ReportData(String targetHost,
                      List<Endpoint>        endpoints,
                      List<Technology>      technologies,
                      List<Secret>          secrets,
                      List<CorsFinding>     corsFindings,
                      List<CloudAsset>      cloudAssets,
                      List<GraphQLEndpoint> graphqlEndpoints) {
        this.targetHost       = targetHost;
        this.generatedAt      = Instant.now();
        this.endpoints        = List.copyOf(endpoints);
        this.technologies     = List.copyOf(technologies);
        this.secrets          = List.copyOf(secrets);
        this.corsFindings     = List.copyOf(corsFindings);
        this.cloudAssets      = List.copyOf(cloudAssets);
        this.graphqlEndpoints = List.copyOf(graphqlEndpoints);
    }

    public int criticalCount() {
        int n = 0;
        for (Secret s : secrets)      if ("CRITICAL".equals(s.severity)) n++;
        for (CorsFinding c : corsFindings) if ("CRITICAL".equals(c.severity)) n++;
        return n;
    }
}
