from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from html import unescape
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup

from .http import HttpClient
from .models import CrawledPage, InputPoint, ScanConfig


@dataclass(frozen=True)
class CrawlResult:
    pages: list[CrawledPage]
    discovered_hosts: tuple[str, ...]


def crawl(config: ScanConfig, client: HttpClient) -> CrawlResult:
    seen: set[str] = set()
    pages: list[CrawledPage] = []
    discovered_hosts: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(config.target, 0)])

    while queue and len(pages) < config.max_pages:
        url, depth = queue.popleft()
        normalized = _normalize_url(url)
        if normalized in seen or not _in_scope(normalized, config.allowed_hosts):
            continue
        seen.add(normalized)

        response = client.request("GET", normalized)
        if response is None:
            continue

        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        pages.append(
            CrawledPage(
                url=normalized,
                status_code=response.status_code,
                title=_title(soup),
                inputs=tuple(_extract_inputs(normalized, soup, config.allowed_hosts)),
            )
        )

        for linked_url in _extract_urls(normalized, soup):
            host = urlparse(linked_url).netloc.lower()
            if host and host not in config.allowed_hosts:
                discovered_hosts.add(host)

        if depth >= config.max_depth:
            continue

        for link in _extract_links(normalized, soup):
            if link not in seen and _in_scope(link, config.allowed_hosts):
                queue.append((link, depth + 1))

    return CrawlResult(pages=pages, discovered_hosts=tuple(sorted(discovered_hosts)))


def _extract_links(base_url: str, soup: BeautifulSoup) -> set[str]:
    links: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        href = str(anchor["href"]).strip()
        if href.startswith(("mailto:", "tel:", "javascript:")):
            continue
        links.add(_normalize_url(urljoin(base_url, href)))
    return links


def _extract_urls(base_url: str, soup: BeautifulSoup) -> set[str]:
    urls: set[str] = set()
    for tag, attr in (
        ("a", "href"),
        ("script", "src"),
        ("link", "href"),
        ("img", "src"),
        ("iframe", "src"),
        ("form", "action"),
    ):
        for element in soup.find_all(tag):
            value = element.get(attr)
            if not value:
                continue
            raw = str(value).strip()
            if raw.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            urls.add(_normalize_url(urljoin(base_url, raw)))
    return urls


def _extract_inputs(page_url: str, soup: BeautifulSoup, allowed_hosts: tuple[str, ...]) -> list[InputPoint]:
    inputs: list[InputPoint] = []

    for name, _value in parse_qsl(urlparse(page_url).query, keep_blank_values=True):
        inputs.append(InputPoint(url=page_url, method="GET", name=name, source="query"))

    for form_index, form in enumerate(soup.find_all("form")):
        method = str(form.get("method", "GET")).upper()
        if method not in {"GET", "POST"}:
            method = "GET"

        action = urljoin(page_url, str(form.get("action") or page_url))
        if not _in_scope(action, allowed_hosts):
            continue
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            field_type = str(field.get("type", "")).lower()
            if field_type in {"submit", "button", "image", "reset", "file"}:
                continue
            inputs.append(
                InputPoint(
                    url=page_url,
                    method=method,  # type: ignore[arg-type]
                    name=unescape(str(name)),
                    source=f"form[{form_index}]",
                    action=action,
                )
            )

    return inputs


def _title(soup: BeautifulSoup) -> str:
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    return ""


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return parsed._replace(scheme=scheme, netloc=netloc, path=path, fragment="").geturl()


def _in_scope(url: str, allowed_hosts: tuple[str, ...]) -> bool:
    host = urlparse(url).netloc.lower()
    return host in allowed_hosts
