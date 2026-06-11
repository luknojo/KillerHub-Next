from __future__ import annotations

import argparse

from rich.console import Console
from rich.table import Table

from .models import EnumerationResult, Finding
from .report import write_html, write_json
from .scanner import run_scan as execute_scan


def main() -> None:
    parser = argparse.ArgumentParser(prog="killerhub")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run an authorized web scan.")
    scan.add_argument("target")
    scan.add_argument("--checks", default="xss,sqli")
    scan.add_argument("--max-pages", type=int, default=30)
    scan.add_argument("--max-depth", type=int, default=2)
    scan.add_argument("--delay", type=float, default=0.2)
    scan.add_argument("--timeout", type=float, default=8.0)
    scan.add_argument("--out", default="killerhub-report.json")
    scan.add_argument("--html")
    scan.add_argument("--allow-host", action="append", default=[])
    scan.add_argument("--enum", action="store_true", help="Run passive target enumeration.")

    lab = subparsers.add_parser("lab", help="Start the intentionally vulnerable local lab.")
    lab.add_argument("--host", default="127.0.0.1")
    lab.add_argument("--port", type=int, default=8088)

    web = subparsers.add_parser("web", help="Start the local KillerHub web console.")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=5000)

    args = parser.parse_args()
    if args.command == "scan":
        run_scan(args)
    elif args.command == "lab":
        from .lab import run as run_lab

        run_lab(host=args.host, port=args.port)
    elif args.command == "web":
        from .web import run as run_web

        run_web(host=args.host, port=args.port)


def run_scan(args: argparse.Namespace) -> None:
    console = Console()
    try:
        result = execute_scan(
            args.target,
            checks=args.checks,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            delay=args.delay,
            timeout=args.timeout,
            allow_hosts=args.allow_host,
            do_enum=args.enum,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    config = result.config
    console.print(f"[bold]Target:[/bold] {config.target}")
    console.print(f"[bold]Scope:[/bold] {', '.join(config.allowed_hosts)}")

    if result.enumeration:
        _print_enumeration(console, result.enumeration)

    console.print(f"[bold]Crawled pages:[/bold] {len(result.pages)}")
    console.print(f"[bold]Inputs found:[/bold] {result.input_count}")
    _print_discovered_hosts(console, result.discovered_hosts)
    write_json(args.out, config, result.pages, result.findings, result.enumeration, result.discovered_hosts)
    if args.html:
        write_html(args.html, config, result.pages, result.findings, result.enumeration, result.discovered_hosts)

    _print_findings(console, result.findings)
    console.print(f"[green]JSON report written to[/green] {args.out}")
    if args.html:
        console.print(f"[green]HTML report written to[/green] {args.html}")


def _print_findings(console: Console, findings: list[Finding]) -> None:
    table = Table(title="Findings")
    table.add_column("Severity")
    table.add_column("Check")
    table.add_column("URL")
    table.add_column("Parameter")
    table.add_column("Evidence")

    for finding in findings:
        table.add_row(
            finding.severity,
            finding.check,
            finding.url,
            finding.parameter,
            finding.evidence,
        )

    if findings:
        console.print(table)
    else:
        console.print("[green]No findings detected by the enabled checks.[/green]")


def _print_enumeration(console: Console, enumeration: EnumerationResult) -> None:
    console.print(f"[bold]Resolved IPs:[/bold] {', '.join(enumeration.ips) or 'unknown'}")
    console.print(f"[bold]Server:[/bold] {enumeration.server or 'unknown'}")
    console.print(f"[bold]X-Powered-By:[/bold] {enumeration.powered_by or 'unknown'}")

    table = Table(title="Detected Technologies")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Confidence")
    table.add_column("Evidence")
    for tech in enumeration.technologies:
        table.add_row(tech.name, tech.category, tech.confidence, tech.evidence)

    if enumeration.technologies:
        console.print(table)
    else:
        console.print("[yellow]No technologies detected by passive fingerprints.[/yellow]")


def _print_discovered_hosts(console: Console, discovered_hosts: tuple[str, ...]) -> None:
    if not discovered_hosts:
        console.print("[green]No out-of-scope hosts identified.[/green]")
        return

    table = Table(title="Identified Hosts Outside Scope")
    table.add_column("Host")
    table.add_column("Action")
    for host in discovered_hosts:
        table.add_row(host, f"Review authorization, then rerun with --allow-host {host}")
    console.print(table)


if __name__ == "__main__":
    main()
