from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from killerhub.http import HttpClient
from killerhub.models import CrawledPage, Finding, InputPoint


PAYLOADS = ("'", '"', "')", '")')
SQL_ERROR_PATTERNS = (
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:\s*mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"postgresql.*error", re.I),
    re.compile(r"sqlite error", re.I),
    re.compile(r"ora-\d{5}", re.I),
)


def run(pages: list[CrawledPage], client: HttpClient) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        for input_point in page.inputs:
            for payload in PAYLOADS:
                text = _send_probe(input_point, payload, client)
                if text is None:
                    continue
                matched = _matched_sql_error(text)
                if matched is None:
                    continue

                findings.append(
                    Finding(
                        check="sqli",
                        severity="high",
                        url=input_point.action or input_point.url,
                        parameter=input_point.name,
                        evidence=f"Database error pattern detected: {matched}",
                        remediation=(
                            "Use parameterized queries, avoid string-built SQL, and return "
                            "generic error messages to users."
                        ),
                    )
                )
                break
    return findings


def _send_probe(input_point: InputPoint, payload: str, client: HttpClient) -> str | None:
    if input_point.method == "GET":
        response = client.request(
            "GET",
            _url_with_param(input_point.action or input_point.url, input_point.name, payload),
        )
    else:
        response = client.request(
            "POST",
            input_point.action or input_point.url,
            data={input_point.name: payload},
        )
    if response is None:
        return None
    return response.text[:200_000]


def _matched_sql_error(text: str) -> str | None:
    for pattern in SQL_ERROR_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def _url_with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    pairs[name] = value
    return urlunparse(parsed._replace(query=urlencode(pairs)))

