from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .checks import sqli, xss
from .crawler import crawl
from .enumeration import enumerate_target
from .http import HttpClient
from .models import CrawledPage, EnumerationResult, Finding, ScanConfig


SUPPORTED_CHECKS = {"xss", "sqli"}


@dataclass(frozen=True)
class ScanResult:
    config: ScanConfig
    pages: list[CrawledPage]
    findings: list[Finding]
    enumeration: EnumerationResult | None
    discovered_hosts: tuple[str, ...]

    @property
    def input_count(self) -> int:
        return sum(len(page.inputs) for page in self.pages)


def run_scan(
    target: str,
    *,
    checks: str = "xss,sqli",
    max_pages: int = 30,
    max_depth: int = 2,
    delay: float = 0.2,
    timeout: float = 8.0,
    allow_hosts: list[str] | None = None,
    do_enum: bool = False,
) -> ScanResult:
    normalized_target = normalize_target(target)
    target_host = urlparse(normalized_target).netloc.lower()
    parsed_checks = parse_checks(checks)
    allowed_hosts = tuple({target_host, *[host.lower() for host in allow_hosts or [] if host]})

    config = ScanConfig(
        target=normalized_target,
        checks=parsed_checks,
        allowed_hosts=allowed_hosts,
        max_pages=max_pages,
        max_depth=max_depth,
        delay=delay,
        timeout=timeout,
    )
    client = HttpClient(timeout=config.timeout, delay=config.delay, user_agent=config.user_agent)

    enumeration = enumerate_target(config.target, client) if do_enum else None
    crawl_result = crawl(config, client)
    pages = crawl_result.pages

    findings: list[Finding] = []
    if "xss" in parsed_checks:
        findings.extend(xss.run(pages, client))
    if "sqli" in parsed_checks:
        findings.extend(sqli.run(pages, client))

    return ScanResult(
        config=config,
        pages=pages,
        findings=_dedupe_findings(findings),
        enumeration=enumeration,
        discovered_hosts=crawl_result.discovered_hosts,
    )


def parse_checks(value: str) -> tuple[str, ...]:
    checks = tuple(check.strip().lower() for check in value.split(",") if check.strip())
    unknown = sorted(set(checks) - SUPPORTED_CHECKS)
    if unknown:
        raise ValueError(f"Unsupported checks: {', '.join(unknown)}")
    return checks


def normalize_target(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be a valid http(s) URL.")
    return value


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.check, finding.url, finding.parameter, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
