from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Severity = Literal["info", "low", "medium", "high"]
Method = Literal["GET", "POST"]


@dataclass(frozen=True)
class InputPoint:
    url: str
    method: Method
    name: str
    source: str
    action: str | None = None


@dataclass(frozen=True)
class CrawledPage:
    url: str
    status_code: int
    title: str
    inputs: tuple[InputPoint, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Finding:
    check: str
    severity: Severity
    url: str
    parameter: str
    evidence: str
    remediation: str


@dataclass(frozen=True)
class Technology:
    name: str
    category: str
    evidence: str
    confidence: str


@dataclass(frozen=True)
class EnumerationResult:
    host: str
    ips: tuple[str, ...]
    status_code: int | None
    final_url: str | None
    server: str | None
    powered_by: str | None
    cookies: tuple[str, ...]
    technologies: tuple[Technology, ...]


@dataclass(frozen=True)
class ScanConfig:
    target: str
    checks: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    max_pages: int = 30
    max_depth: int = 2
    delay: float = 0.2
    timeout: float = 8.0
    user_agent: str = "KillerHub-Next/0.1 authorized-security-scan"
