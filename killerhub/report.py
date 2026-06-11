from __future__ import annotations

import json
from dataclasses import asdict
from html import escape
from pathlib import Path

from .models import CrawledPage, EnumerationResult, Finding, ScanConfig


def write_json(
    path: str,
    config: ScanConfig,
    pages: list[CrawledPage],
    findings: list[Finding],
    enumeration: EnumerationResult | None = None,
    discovered_hosts: tuple[str, ...] = (),
) -> None:
    output = {
        "target": config.target,
        "checks": config.checks,
        "scope": config.allowed_hosts,
        "pages_scanned": len(pages),
        "inputs_found": sum(len(page.inputs) for page in pages),
        "discovered_hosts": discovered_hosts,
        "enumeration": asdict(enumeration) if enumeration else None,
        "pages": [asdict(page) for page in pages],
        "findings": [asdict(finding) for finding in findings],
    }
    Path(path).write_text(json.dumps(output, indent=2), encoding="utf-8")


def write_html(
    path: str,
    config: ScanConfig,
    pages: list[CrawledPage],
    findings: list[Finding],
    enumeration: EnumerationResult | None = None,
    discovered_hosts: tuple[str, ...] = (),
) -> None:
    rows = "\n".join(_finding_row(finding) for finding in findings)
    if not rows:
        rows = "<tr><td colspan='5'>No findings detected.</td></tr>"
    enum_section = _enum_section(enumeration)
    page_rows = "\n".join(_page_row(page) for page in pages)
    if not page_rows:
        page_rows = "<tr><td colspan='4'>No pages crawled.</td></tr>"
    discovered_section = _discovered_hosts_section(discovered_hosts)

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>KillerHub Next Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2937; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    .high {{ color: #991b1b; font-weight: 700; }}
    .medium {{ color: #92400e; font-weight: 700; }}
    .low {{ color: #1d4ed8; font-weight: 700; }}
  </style>
</head>
<body>
  <h1>KillerHub Next Report</h1>
  <p><strong>Target:</strong> {escape(config.target)}</p>
  <p><strong>Checks:</strong> {escape(', '.join(config.checks))}</p>
  <p><strong>Scope:</strong> {escape(', '.join(config.allowed_hosts))}</p>
  <p><strong>Pages scanned:</strong> {len(pages)}</p>
  <p><strong>Inputs found:</strong> {sum(len(page.inputs) for page in pages)}</p>
  {discovered_section}
  {enum_section}
  <h2>Crawled Pages</h2>
  <table>
    <thead>
      <tr>
        <th>Status</th>
        <th>URL</th>
        <th>Title</th>
        <th>Inputs</th>
      </tr>
    </thead>
    <tbody>
      {page_rows}
    </tbody>
  </table>
  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Check</th>
        <th>URL</th>
        <th>Parameter</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""
    Path(path).write_text(html, encoding="utf-8")


def _finding_row(finding: Finding) -> str:
    return (
        "<tr>"
        f"<td class='{escape(finding.severity)}'>{escape(finding.severity)}</td>"
        f"<td>{escape(finding.check)}</td>"
        f"<td>{escape(finding.url)}</td>"
        f"<td>{escape(finding.parameter)}</td>"
        f"<td>{escape(finding.evidence)}</td>"
        "</tr>"
    )


def _page_row(page: CrawledPage) -> str:
    inputs = ", ".join(f"{item.method}:{item.name}" for item in page.inputs) or "none"
    return (
        "<tr>"
        f"<td>{page.status_code}</td>"
        f"<td>{escape(page.url)}</td>"
        f"<td>{escape(page.title)}</td>"
        f"<td>{escape(inputs)}</td>"
        "</tr>"
    )


def _discovered_hosts_section(discovered_hosts: tuple[str, ...]) -> str:
    if not discovered_hosts:
        return """
  <h2>Discovered Hosts</h2>
  <p>No out-of-scope hosts were identified from in-scope pages.</p>
"""
    items = "".join(f"<li>{escape(host)}</li>" for host in discovered_hosts)
    return f"""
  <h2>Discovered Hosts</h2>
  <p>These hosts were identified passively but were not tested because they are outside the current scope.</p>
  <ul>{items}</ul>
"""


def _enum_section(enumeration: EnumerationResult | None) -> str:
    if enumeration is None:
        return ""

    tech_rows = "\n".join(
        "<tr>"
        f"<td>{escape(tech.name)}</td>"
        f"<td>{escape(tech.category)}</td>"
        f"<td>{escape(tech.confidence)}</td>"
        f"<td>{escape(tech.evidence)}</td>"
        "</tr>"
        for tech in enumeration.technologies
    )
    if not tech_rows:
        tech_rows = "<tr><td colspan='4'>No technologies detected.</td></tr>"

    return f"""
  <h2>Enumeration</h2>
  <p><strong>Host:</strong> {escape(enumeration.host)}</p>
  <p><strong>IPs:</strong> {escape(', '.join(enumeration.ips) or 'unknown')}</p>
  <p><strong>Status:</strong> {escape(str(enumeration.status_code or 'unknown'))}</p>
  <p><strong>Final URL:</strong> {escape(enumeration.final_url or 'unknown')}</p>
  <p><strong>Server:</strong> {escape(enumeration.server or 'unknown')}</p>
  <p><strong>X-Powered-By:</strong> {escape(enumeration.powered_by or 'unknown')}</p>
  <p><strong>Cookies:</strong> {escape(', '.join(enumeration.cookies) or 'none')}</p>
  <h3>Technologies</h3>
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Category</th>
        <th>Confidence</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      {tech_rows}
    </tbody>
  </table>
"""
