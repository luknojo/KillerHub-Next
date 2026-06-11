from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, redirect, render_template_string, request, send_file, url_for

from .report import write_html, write_json
from .scanner import ScanResult, run_scan


REPORT_DIR = Path("reports")
LAST_RESULT: ScanResult | None = None
LAST_JSON: Path | None = None
LAST_HTML: Path | None = None
LAST_ERROR: str | None = None


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> str:
        return render_template_string(
            WEB_LAYOUT,
            result=LAST_RESULT,
            error=LAST_ERROR,
            json_path=LAST_JSON,
            html_path=LAST_HTML,
        )

    @app.post("/scan")
    def scan() -> Response:
        global LAST_ERROR, LAST_HTML, LAST_JSON, LAST_RESULT

        target = request.form.get("target", "").strip()
        checks = ",".join(request.form.getlist("checks")) or "xss,sqli"
        allow_hosts = [
            host.strip()
            for host in request.form.get("allow_hosts", "").splitlines()
            if host.strip()
        ]
        try:
            result = run_scan(
                target,
                checks=checks,
                max_pages=int(request.form.get("max_pages", "30")),
                max_depth=int(request.form.get("max_depth", "2")),
                delay=float(request.form.get("delay", "0.2")),
                timeout=float(request.form.get("timeout", "8")),
                allow_hosts=allow_hosts,
                do_enum=request.form.get("enum") == "on",
            )
            REPORT_DIR.mkdir(exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            LAST_JSON = REPORT_DIR / f"killerhub-{stamp}.json"
            LAST_HTML = REPORT_DIR / f"killerhub-{stamp}.html"
            write_json(
                str(LAST_JSON),
                result.config,
                result.pages,
                result.findings,
                result.enumeration,
                result.discovered_hosts,
            )
            write_html(
                str(LAST_HTML),
                result.config,
                result.pages,
                result.findings,
                result.enumeration,
                result.discovered_hosts,
            )
            LAST_RESULT = result
            LAST_ERROR = None
        except Exception as exc:
            LAST_ERROR = str(exc)
        return redirect(url_for("index"))

    @app.post("/scan-discovered")
    def scan_discovered() -> Response:
        global LAST_ERROR, LAST_HTML, LAST_JSON, LAST_RESULT
        if LAST_RESULT is None:
            LAST_ERROR = "No previous scan is available."
            return redirect(url_for("index"))

        selected_hosts = request.form.getlist("hosts")
        allowed_hosts = sorted({*LAST_RESULT.config.allowed_hosts, *selected_hosts})
        try:
            result = run_scan(
                LAST_RESULT.config.target,
                checks=",".join(LAST_RESULT.config.checks),
                max_pages=LAST_RESULT.config.max_pages,
                max_depth=LAST_RESULT.config.max_depth,
                delay=LAST_RESULT.config.delay,
                timeout=LAST_RESULT.config.timeout,
                allow_hosts=allowed_hosts,
                do_enum=LAST_RESULT.enumeration is not None,
            )
            REPORT_DIR.mkdir(exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            LAST_JSON = REPORT_DIR / f"killerhub-{stamp}.json"
            LAST_HTML = REPORT_DIR / f"killerhub-{stamp}.html"
            write_json(
                str(LAST_JSON),
                result.config,
                result.pages,
                result.findings,
                result.enumeration,
                result.discovered_hosts,
            )
            write_html(
                str(LAST_HTML),
                result.config,
                result.pages,
                result.findings,
                result.enumeration,
                result.discovered_hosts,
            )
            LAST_RESULT = result
            LAST_ERROR = None
        except Exception as exc:
            LAST_ERROR = str(exc)
        return redirect(url_for("index"))

    @app.get("/report/json")
    def report_json() -> Response:
        if LAST_JSON is None or not LAST_JSON.exists():
            return Response("No JSON report available.", status=404)
        return send_file(LAST_JSON.resolve(), as_attachment=True)

    @app.get("/report/html")
    def report_html() -> Response:
        if LAST_HTML is None or not LAST_HTML.exists():
            return Response("No HTML report available.", status=404)
        return send_file(LAST_HTML.resolve(), as_attachment=True)

    @app.get("/api/last")
    def api_last() -> dict[str, object]:
        if LAST_RESULT is None:
            return {"result": None}
        return {
            "target": LAST_RESULT.config.target,
            "pages": [asdict(page) for page in LAST_RESULT.pages],
            "findings": [asdict(finding) for finding in LAST_RESULT.findings],
            "enumeration": asdict(LAST_RESULT.enumeration) if LAST_RESULT.enumeration else None,
            "discovered_hosts": LAST_RESULT.discovered_hosts,
        }

    return app


def run(host: str = "127.0.0.1", port: int = 5000) -> None:
    create_app().run(host=host, port=port, debug=False)


WEB_LAYOUT = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KillerHub Console</title>
  <style>
    :root { font-family: Inter, Segoe UI, Arial, sans-serif; color: #202124; background: #f5f6f3; }
    * { box-sizing: border-box; }
    body { margin: 0; }
    header { height: 58px; display: flex; align-items: center; justify-content: space-between; padding: 0 24px; background: #fff; border-bottom: 1px solid #dcded6; }
    main { display: grid; grid-template-columns: 360px 1fr; min-height: calc(100vh - 58px); }
    aside { border-right: 1px solid #dcded6; background: #ffffff; padding: 20px; }
    section { padding: 20px; }
    h1, h2, h3 { margin: 0; }
    h1 { font-size: 20px; }
    h2 { font-size: 16px; margin-bottom: 12px; }
    h3 { font-size: 14px; margin: 18px 0 10px; }
    label { display: grid; gap: 6px; margin-bottom: 12px; font-size: 13px; color: #4b5563; }
    input, textarea { width: 100%; border: 1px solid #c8cbc1; border-radius: 6px; padding: 10px; font: inherit; background: #fff; color: #202124; }
    input[type="checkbox"] { width: auto; }
    textarea { min-height: 78px; resize: vertical; }
    button, .button { display: inline-flex; align-items: center; justify-content: center; min-height: 38px; border: 0; border-radius: 6px; padding: 0 14px; background: #0f766e; color: #fff; text-decoration: none; font: inherit; cursor: pointer; }
    .secondary { background: #334155; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .checks { display: flex; gap: 12px; margin-bottom: 12px; }
    .checks label { display: inline-flex; align-items: center; gap: 6px; margin: 0; }
    .summary { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; margin-bottom: 18px; }
    .metric, .panel, .finding, table { background: #fff; border: 1px solid #dcded6; border-radius: 8px; }
    .metric { padding: 14px; }
    .metric strong { display: block; font-size: 26px; margin-top: 6px; }
    .panel { padding: 16px; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; overflow: hidden; }
    th, td { padding: 10px; border-bottom: 1px solid #eceee8; text-align: left; vertical-align: top; font-size: 13px; }
    th { background: #fafaf8; color: #4b5563; }
    tr:last-child td { border-bottom: 0; }
    .finding { padding: 12px; margin-bottom: 10px; }
    .severity { display: inline-block; border-radius: 999px; padding: 3px 8px; font-size: 12px; color: #fff; background: #64748b; }
    .high { background: #b91c1c; }
    .medium { background: #b45309; }
    .low { background: #1d4ed8; }
    .info { background: #475569; }
    .error { padding: 10px; color: #991b1b; background: #fee2e2; border-radius: 6px; margin-bottom: 12px; }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; }
    .muted { color: #6b7280; }
    @media (max-width: 900px) {
      main { grid-template-columns: 1fr; }
      aside { border-right: 0; border-bottom: 1px solid #dcded6; }
      .summary { grid-template-columns: 1fr 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <h1>KillerHub Console</h1>
    <span class="muted">localhost</span>
  </header>
  <main>
    <aside>
      <form action="/scan" method="post">
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <label>Target
          <input name="target" value="http://127.0.0.1:8088" required>
        </label>
        <div class="checks">
          <label><input type="checkbox" name="checks" value="xss" checked> XSS</label>
          <label><input type="checkbox" name="checks" value="sqli" checked> SQLi</label>
          <label><input type="checkbox" name="enum" checked> Enum</label>
        </div>
        <div class="row">
          <label>Max pages
            <input name="max_pages" type="number" value="30" min="1" max="500">
          </label>
          <label>Max depth
            <input name="max_depth" type="number" value="2" min="0" max="10">
          </label>
        </div>
        <div class="row">
          <label>Delay
            <input name="delay" type="number" value="0.2" min="0" step="0.1">
          </label>
          <label>Timeout
            <input name="timeout" type="number" value="8" min="1" step="1">
          </label>
        </div>
        <label>Allowed hosts
          <textarea name="allow_hosts" placeholder="api.example.test"></textarea>
        </label>
        <button type="submit">Run scan</button>
      </form>
    </aside>
    <section>
      {% if result %}
        <div class="summary">
          <div class="metric"><span>Findings</span><strong>{{ result.findings|length }}</strong></div>
          <div class="metric"><span>Pages</span><strong>{{ result.pages|length }}</strong></div>
          <div class="metric"><span>Inputs</span><strong>{{ result.input_count }}</strong></div>
          <div class="metric"><span>Scope</span><strong>{{ result.config.allowed_hosts|length }}</strong></div>
          <div class="metric"><span>Hosts Found</span><strong>{{ result.discovered_hosts|length }}</strong></div>
        </div>
        <div class="actions panel">
          <a class="button" href="/report/json">Download JSON</a>
          <a class="button secondary" href="/report/html">Download HTML</a>
          <a class="button secondary" href="{{ result.config.target }}" target="_blank" rel="noreferrer">Open target</a>
        </div>
        {% if result.enumeration %}
          <div class="panel">
            <h2>Enumeration</h2>
            <p><strong>IPs:</strong> {{ result.enumeration.ips|join(', ') or 'unknown' }}</p>
            <p><strong>Server:</strong> {{ result.enumeration.server or 'unknown' }}</p>
            <p><strong>X-Powered-By:</strong> {{ result.enumeration.powered_by or 'unknown' }}</p>
            <table>
              <thead><tr><th>Technology</th><th>Category</th><th>Confidence</th><th>Evidence</th></tr></thead>
              <tbody>
                {% for tech in result.enumeration.technologies %}
                  <tr><td>{{ tech.name }}</td><td>{{ tech.category }}</td><td>{{ tech.confidence }}</td><td>{{ tech.evidence }}</td></tr>
                {% else %}
                  <tr><td colspan="4">No technologies detected.</td></tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        {% endif %}
        <div class="panel">
          <h2>Identified Hosts</h2>
          {% if result.discovered_hosts %}
            <p class="muted">These hosts were seen from in-scope pages but were not tested. Select only hosts you are authorized to test.</p>
            <form action="/scan-discovered" method="post">
              <table>
                <thead><tr><th>Allow</th><th>Host</th><th>Status</th></tr></thead>
                <tbody>
                  {% for host in result.discovered_hosts %}
                    <tr>
                      <td><input type="checkbox" name="hosts" value="{{ host }}"></td>
                      <td>{{ host }}</td>
                      <td>identified, not tested</td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
              <div style="margin-top: 12px;"><button type="submit">Allow selected and rescan</button></div>
            </form>
          {% else %}
            <p class="muted">No out-of-scope hosts identified.</p>
          {% endif %}
        </div>
        <div class="panel">
          <h2>Findings</h2>
          {% for finding in result.findings %}
            <div class="finding">
              <span class="severity {{ finding.severity }}">{{ finding.severity }}</span>
              <strong>{{ finding.check }}</strong>
              <p>{{ finding.url }} - {{ finding.parameter }}</p>
              <p>{{ finding.evidence }}</p>
              <p class="muted">{{ finding.remediation }}</p>
            </div>
          {% else %}
            <p class="muted">No findings detected.</p>
          {% endfor %}
        </div>
        <div class="panel">
          <h2>Crawled Pages</h2>
          <table>
            <thead><tr><th>Status</th><th>URL</th><th>Title</th><th>Inputs</th></tr></thead>
            <tbody>
              {% for page in result.pages %}
                <tr>
                  <td>{{ page.status_code }}</td>
                  <td>{{ page.url }}</td>
                  <td>{{ page.title }}</td>
                  <td>{{ page.inputs|length }}</td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      {% else %}
        <div class="panel">
          <h2>Ready</h2>
          <p class="muted">Start the lab on port 8088, then run a scan from the form.</p>
        </div>
      {% endif %}
    </section>
  </main>
</body>
</html>"""
