from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .http import HttpClient
from .models import EnumerationResult, Technology


def enumerate_target(target: str, client: HttpClient) -> EnumerationResult:
    host = urlparse(target).hostname or ""
    ips = _resolve_ips(host)
    response = client.request("GET", target)

    if response is None:
        return EnumerationResult(
            host=host,
            ips=ips,
            status_code=None,
            final_url=None,
            server=None,
            powered_by=None,
            cookies=(),
            technologies=(),
        )

    headers = {key.lower(): value for key, value in response.headers.items()}
    soup = BeautifulSoup(response.text, "html.parser")
    technologies = _detect_technologies(headers, response.text, soup)

    return EnumerationResult(
        host=host,
        ips=ips,
        status_code=response.status_code,
        final_url=response.url,
        server=response.headers.get("server"),
        powered_by=response.headers.get("x-powered-by"),
        cookies=tuple(response.cookies.keys()),
        technologies=tuple(technologies),
    )


def _resolve_ips(host: str) -> tuple[str, ...]:
    if not host:
        return ()
    try:
        results = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return ()
    return tuple(sorted({item[4][0] for item in results}))


def _detect_technologies(
    headers: dict[str, str],
    body: str,
    soup: BeautifulSoup,
) -> list[Technology]:
    found: dict[str, Technology] = {}

    def add(name: str, category: str, evidence: str, confidence: str = "medium") -> None:
        found.setdefault(name, Technology(name, category, evidence, confidence))

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    generator = _meta_content(soup, "generator")
    body_lower = body.lower()

    header_rules = (
        ("nginx", "Web Server", server, "Server header"),
        ("apache", "Web Server", server, "Server header"),
        ("cloudflare", "CDN/WAF", server + headers.get("cf-ray", ""), "Server/CF headers"),
        ("express", "Backend", powered_by, "X-Powered-By header"),
        ("php", "Backend", powered_by + headers.get("set-cookie", ""), "X-Powered-By/cookie"),
        ("asp.net", "Backend", powered_by + headers.get("set-cookie", ""), "X-Powered-By/cookie"),
    )
    for needle, category, haystack, evidence in header_rules:
        if needle in haystack.lower():
            add(_display_name(needle), category, evidence, "high")

    if generator:
        add(generator.split()[0], "CMS/Generator", "generator meta tag", "medium")

    script_sources = " ".join(
        str(tag.get("src", "")) for tag in soup.find_all("script") if tag.get("src")
    ).lower()
    stylesheet_sources = " ".join(
        str(tag.get("href", "")) for tag in soup.find_all("link") if tag.get("href")
    ).lower()
    asset_text = f"{script_sources} {stylesheet_sources} {body_lower[:120_000]}"

    asset_rules = (
        ("wp-content", "WordPress", "CMS", "WordPress asset path"),
        ("react", "React", "Frontend", "React script/signature"),
        ("vue", "Vue.js", "Frontend", "Vue script/signature"),
        ("angular", "Angular", "Frontend", "Angular script/signature"),
        ("jquery", "jQuery", "JavaScript Library", "jQuery asset/signature"),
        ("bootstrap", "Bootstrap", "UI Framework", "Bootstrap asset/signature"),
        ("next/static", "Next.js", "Frontend Framework", "Next.js asset path"),
        ("nuxt", "Nuxt", "Frontend Framework", "Nuxt asset/signature"),
        ("laravel", "Laravel", "Backend", "Laravel cookie/signature"),
        ("django", "Django", "Backend", "Django cookie/signature"),
    )
    for needle, name, category, evidence in asset_rules:
        if needle in asset_text:
            add(name, category, evidence)

    if re.search(r"data-reactroot|__react|react-dom", body, re.I):
        add("React", "Frontend", "React DOM signature")
    if re.search(r"ng-version|_ngcontent-|ng-app", body, re.I):
        add("Angular", "Frontend", "Angular DOM signature")
    if re.search(r"data-v-|__vue__", body, re.I):
        add("Vue.js", "Frontend", "Vue DOM signature")

    return sorted(found.values(), key=lambda tech: (tech.category, tech.name))


def _meta_content(soup: BeautifulSoup, name: str) -> str | None:
    tag = soup.find("meta", attrs={"name": re.compile(f"^{re.escape(name)}$", re.I)})
    if not tag:
        return None
    content = tag.get("content")
    return str(content).strip() if content else None


def _display_name(value: str) -> str:
    names = {
        "asp.net": "ASP.NET",
        "cloudflare": "Cloudflare",
        "express": "Express",
        "nginx": "nginx",
        "apache": "Apache",
        "php": "PHP",
    }
    return names.get(value, value.title())

