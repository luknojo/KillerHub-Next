from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from killerhub.http import HttpClient
from killerhub.models import CrawledPage, Finding, InputPoint


MARKER = "khxss_7d21_probe"
PAYLOAD = f"<{MARKER}>"


def run(pages: list[CrawledPage], client: HttpClient) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        for input_point in page.inputs:
            response_text = _send_probe(input_point, client)
            if response_text is None:
                continue

            if PAYLOAD in response_text:
                findings.append(
                    Finding(
                        check="xss",
                        severity="medium",
                        url=input_point.action or input_point.url,
                        parameter=input_point.name,
                        evidence="Probe marker was reflected without HTML escaping.",
                        remediation=(
                            "Encode untrusted output by context, validate inputs, and consider "
                            "a strict Content Security Policy."
                        ),
                    )
                )
    return findings


def _send_probe(input_point: InputPoint, client: HttpClient) -> str | None:
    if input_point.method == "GET":
        target = input_point.action or input_point.url
        response = client.request("GET", _url_with_param(target, input_point.name, PAYLOAD))
    else:
        response = client.request(
            "POST",
            input_point.action or input_point.url,
            data={input_point.name: PAYLOAD},
        )

    if response is None:
        return None
    return response.text


def _url_with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    pairs[name] = value
    return urlunparse(parsed._replace(query=urlencode(pairs)))

