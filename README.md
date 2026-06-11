# KillerHub Next

KillerHub Next is a defensive web security learning project focused on authorized testing.
It crawls in-scope pages, identifies user-controlled inputs, runs conservative XSS and SQL
Injection probes, and writes structured reports that are easy to review.

> Use only on applications you own or have explicit permission to test.

## What changed from the original idea

- Clear CLI entry point instead of one large script.
- Same-origin crawling with page and depth limits.
- Rate limiting, timeouts, and deterministic request handling.
- Separated checks for XSS and SQL Injection.
- Evidence-based findings with severity and remediation text.
- Complete JSON and HTML reports with enumeration, crawled pages, inputs, and findings.
- Safer XSS detection based on reflected marker analysis instead of executing JavaScript.
- Local vulnerable lab and localhost web console.
- Passive out-of-scope host discovery with explicit allow-and-rescan flow.

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

## Run

```powershell
killerhub scan https://example.com --checks xss,sqli --max-pages 30 --out report.json
```

Run with passive enumeration:

```powershell
killerhub scan https://example.com --enum --checks xss,sqli --out report.json --html report.html
```

Or without installing the package:

```powershell
python -m killerhub.cli scan https://example.com --checks xss,sqli --max-pages 30
```

## Local lab

Start the intentionally vulnerable training site:

```powershell
killerhub lab
```

The lab runs at:

```text
http://127.0.0.1:8088
```

It includes simple vulnerable flows for reflected XSS, SQL error detection, forms, cookies, and technology fingerprinting.

## Web console

Start the local dashboard:

```powershell
killerhub web
```

Open:

```text
http://127.0.0.1:5000
```

From the console you can configure the target, enabled checks, enumeration, crawl limits, allowed hosts, and download JSON/HTML reports.

If the crawler sees links, assets, or form actions pointing to hosts outside the current scope, the console lists them under "Identified Hosts". They are not tested automatically. Select the hosts you are authorized to test and use "Allow selected and rescan" to include them.

## Test from CLI

With the lab running in another terminal:

```powershell
killerhub scan http://127.0.0.1:8088 --enum --max-pages 10 --out lab-report.json --html lab-report.html
```

## CLI options

- `target`: Base URL to scan.
- `--checks`: Comma-separated checks. Supported: `xss`, `sqli`.
- `--max-pages`: Maximum pages to crawl.
- `--max-depth`: Maximum link depth from the target.
- `--delay`: Delay in seconds between HTTP requests.
- `--timeout`: Per-request timeout.
- `--out`: JSON report path.
- `--html`: Optional HTML report path.
- `--allow-host`: Extra host allowed in scope. Can be used more than once.
- `--enum`: Runs passive enumeration for IPs, headers, cookies, and basic technology fingerprints.

## Reports

Reports include:

- Target, scope, enabled checks, pages scanned, and input count.
- Passive enumeration results.
- Out-of-scope hosts identified passively from in-scope pages.
- Every crawled page and its discovered inputs.
- Findings with severity, URL, parameter, evidence, and remediation.

## Passive enumeration

The enumeration mode collects low-noise signals:

- DNS resolution for the target host.
- HTTP status, final URL after redirects, `Server`, and `X-Powered-By`.
- Cookie names set by the first response.
- Basic technology hints from headers, generator meta tags, scripts, stylesheets, and HTML signatures.

This is intentionally lighter than Wappalyzer. It is designed to be understandable and easy to extend while avoiding aggressive probing.

## Roadmap

- Add robots.txt awareness mode.
- Add authentication profiles using exported cookies.
- Add Playwright-based DOM XSS checks for local labs.
- Expand technology fingerprints with a local rules file.
- Add unit tests with a small intentionally vulnerable local app.
- Add SARIF export for GitHub code scanning style workflows.
