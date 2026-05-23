package burp.utils;

import burp.models.ReportData;

public class HtmlReportWriter {

    public static String write(ReportData data) {
        String jsonData = JsonReportWriter.write(data);

        return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n" +
            "<meta charset=\"UTF-8\">\n" +
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
            "<title>ReconMaster Pro — " + escHtml(data.targetHost) + "</title>\n" +
            "<style>" + CSS + "</style>\n" +
            "</head>\n<body>\n" +
            "<header><h1>ReconMaster Pro</h1>" +
            "<p class=\"meta\">Target: <strong>" + escHtml(data.targetHost) + "</strong> &nbsp;|&nbsp; " +
            "Generated: <strong>" + escHtml(data.generatedAt.toString()) + "</strong></p></header>\n" +
            "<nav id=\"nav\"></nav>\n" +
            "<main id=\"main\"></main>\n" +
            "<script>\n" +
            "const REPORT_DATA = " + jsonData + ";\n" +
            RENDER_JS +
            "\n</script>\n" +
            "</body>\n</html>";
    }

    private static String escHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    // ── Inline CSS ────────────────────────────────────────────────────────

    private static final String CSS = """
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #f5f6fa; color: #2d3436; font-size: 14px; }
        header { background: #2d3436; color: #fff; padding: 16px 24px; }
        header h1 { font-size: 22px; }
        header .meta { margin-top: 4px; font-size: 12px; color: #b2bec3; }
        nav { display: flex; gap: 4px; padding: 12px 24px;
              background: #fff; border-bottom: 1px solid #dfe6e9; }
        nav button { padding: 6px 14px; border: 1px solid #b2bec3; background: #fff;
                     border-radius: 4px; cursor: pointer; font-size: 13px; }
        nav button.active { background: #0984e3; color: #fff; border-color: #0984e3; }
        main { padding: 20px 24px; }
        section { display: none; }
        section.active { display: block; }
        h2 { font-size: 18px; margin-bottom: 12px; }
        .summary-grid { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
        .card { background: #fff; border-radius: 8px; padding: 16px 20px;
                box-shadow: 0 1px 4px rgba(0,0,0,.08); min-width: 130px; text-align: center; }
        .card .num { font-size: 28px; font-weight: 700; color: #0984e3; }
        .card .label { font-size: 12px; color: #636e72; margin-top: 2px; }
        table { width: 100%; border-collapse: collapse; background: #fff;
                border-radius: 8px; overflow: hidden;
                box-shadow: 0 1px 4px rgba(0,0,0,.08); }
        th { background: #2d3436; color: #fff; padding: 10px 12px;
             text-align: left; font-size: 12px; font-weight: 600; }
        td { padding: 9px 12px; border-bottom: 1px solid #f0f0f0;
             font-size: 13px; word-break: break-word; max-width: 320px; }
        tr:hover td { background: #f8f9ff; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
                 font-size: 11px; font-weight: 700; }
        .CRITICAL { background: #ff7675; color: #fff; }
        .HIGH     { background: #fd9644; color: #fff; }
        .MEDIUM   { background: #ffeaa7; color: #636e72; }
        .LOW      { background: #55efc4; color: #2d3436; }
        .PUBLIC   { background: #ff7675; color: #fff; }
        .PRIVATE  { background: #55efc4; color: #2d3436; }
        .empty    { color: #b2bec3; font-style: italic; padding: 16px 0; }
        """;

    // ── Vanilla JS renderer ───────────────────────────────────────────────

    private static final String RENDER_JS = """
        const d = REPORT_DATA;
        const sections = ['summary','endpoints','technologies','secrets','cors','cloudAssets'];
        const labels   = ['Summary','Endpoints','Technologies','Secrets','CORS','Cloud Assets'];

        // nav tabs
        const nav = document.getElementById('nav');
        sections.forEach((id, i) => {
            const btn = document.createElement('button');
            btn.textContent = labels[i];
            btn.onclick = () => activate(id);
            btn.id = 'btn-' + id;
            nav.appendChild(btn);
        });

        // sections container
        const main = document.getElementById('main');
        sections.forEach(id => {
            const sec = document.createElement('section');
            sec.id = 'sec-' + id;
            main.appendChild(sec);
        });

        function activate(id) {
            sections.forEach(s => {
                document.getElementById('sec-' + s).className = s === id ? 'active' : '';
                document.getElementById('btn-' + s).className = s === id ? 'active' : '';
            });
            render(id);
        }

        function esc(s) {
            if (s == null) return '';
            return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }

        function badge(sev) {
            return '<span class="badge ' + esc(sev) + '">' + esc(sev) + '</span>';
        }

        function table(headers, rows) {
            if (!rows.length) return '<p class="empty">No data collected.</p>';
            return '<table><thead><tr>' +
                headers.map(h => '<th>' + esc(h) + '</th>').join('') +
                '</tr></thead><tbody>' +
                rows.map(r => '<tr>' + r.map(c => '<td>' + c + '</td>').join('') + '</tr>').join('') +
                '</tbody></table>';
        }

        function render(id) {
            const sec = document.getElementById('sec-' + id);
            switch(id) {
                case 'summary':
                    sec.innerHTML = '<h2>Summary</h2><div class="summary-grid">' +
                        card(d.endpoints.length, 'Endpoints') +
                        card(d.technologies.length, 'Technologies') +
                        card(d.secrets.length, 'Secrets') +
                        card(d.corsFindings.length, 'CORS Findings') +
                        card(d.cloudAssets.length, 'Cloud Assets') +
                        card(d.graphqlEndpoints.length, 'GraphQL') +
                    '</div>'; break;

                case 'endpoints':
                    sec.innerHTML = '<h2>Endpoints (' + d.endpoints.length + ')</h2>' +
                    table(
                        ['Host','Method','Path','Pattern','Risk','Status'],
                        d.endpoints.map(e => [
                            esc(e.host), esc(e.method), esc(e.path),
                            esc(e.patternGroup), e.riskScore, e.statusCode
                        ])
                    ); break;

                case 'technologies':
                    sec.innerHTML = '<h2>Technologies (' + d.technologies.length + ')</h2>' +
                    table(
                        ['Name','Version','Category','Host','Highest CVE','CVEs'],
                        d.technologies.map(t => [
                            esc(t.name), esc(t.version), esc(t.category),
                            esc(t.host), badge(t.cves.length ? t.cves[0].severity : null),
                            t.cves.length
                        ])
                    ); break;

                case 'secrets':
                    sec.innerHTML = '<h2>Secrets (' + d.secrets.length + ')</h2>' +
                    table(
                        ['Severity','Type','Value','Host','URL','Detected By'],
                        d.secrets.map(s => [
                            badge(s.severity), esc(s.type),
                            '<code>' + esc(s.value) + '</code>',
                            esc(s.host), esc(s.url), esc(s.detectedBy)
                        ])
                    ); break;

                case 'cors':
                    sec.innerHTML = '<h2>CORS Findings (' + d.corsFindings.length + ')</h2>' +
                    table(
                        ['Severity','Type','Host','URL','Method','ACAO','Probe'],
                        d.corsFindings.map(c => [
                            badge(c.severity), esc(c.type),
                            esc(c.host), esc(c.url), esc(c.method),
                            esc(c.responseAcao),
                            c.activeProbe ? 'active' : 'passive'
                        ])
                    ); break;

                case 'cloudAssets':
                    sec.innerHTML = '<h2>Cloud Assets (' + d.cloudAssets.length + ')</h2>' +
                    table(
                        ['Provider','Bucket/Account','Access','Source','Asset URL'],
                        d.cloudAssets.map(a => [
                            esc(a.provider ? a.provider.displayName : ''),
                            esc(a.bucketOrAccount),
                            '<span class="badge ' + esc(a.accessStatus) + '">' +
                                esc(a.accessStatus) + '</span>',
                            esc(a.sourceType), esc(a.url)
                        ])
                    ); break;
            }
        }

        function card(num, label) {
            return '<div class="card"><div class="num">' + num +
                   '</div><div class="label">' + esc(label) + '</div></div>';
        }

        activate('summary');
        """;
}
