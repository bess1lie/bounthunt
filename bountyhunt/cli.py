from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from bountyhunt import __author__, __version__
from bountyhunt.core.db import Database
from bountyhunt.core.scope import Scope
from bountyhunt.modules.content import ContentPipeline
from bountyhunt.modules.monitor import get_diff_summary, run_monitor
from bountyhunt.modules.notify import DiffSummary
from bountyhunt.modules.portscan import PortScanPipeline
from bountyhunt.modules.recon import ReconPipeline
from bountyhunt.modules.secrets import SecretsPipeline
from bountyhunt.modules.techdetect import display_tech_table
from bountyhunt.modules.vuln import NucleiPipeline
from bountyhunt.report.render import generate_report

app = typer.Typer(
    name="bountyhunt",
    help="Automated recon and monitoring CLI for bug bounty programs",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        rprint(f"[bold]bountyhunt[/bold] v{__version__} — by {__author__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show version and exit",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


@app.command()
def init(
    scope_file: Path = typer.Argument(
        "scope.yaml",
        help="Path to create scope file at",
    ),
) -> None:
    """Create a template scope.yaml file."""
    Scope.create_template(scope_file)
    rprint(f"[green]✓[/green] Created scope template at [bold]{scope_file}[/bold]")
    rprint("Edit the file to add your target domains.")


@app.command()
def scan(
    scope_file: Path = typer.Argument(
        ...,
        help="Path to scope YAML file",
        exists=True,
    ),
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="Specific target domain (overrides scope)",
    ),
    all_mode: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Full pipeline: recon + portscan + nuclei + content + secrets + techdetect",
    ),
    rate: int = typer.Option(
        100,
        "--rate",
        "-r",
        help="Packets per second for port scan (naabu)",
    ),
    severity: str = typer.Option(
        "low,medium,high,critical",
        "--severity",
        "-s",
        help="Nuclei severity filter (comma-separated)",
    ),
    include_intrusive: bool = typer.Option(
        False,
        "--include-intrusive",
        help="Enable nuclei templates tagged dos/fuzz/intrusive (unsafe)",
    ),
    show_full_secrets: bool = typer.Option(
        False,
        "--show-full-secrets",
        help="Store and display raw secret values (exposes credentials — use with caution)",
    ),
    db_path: Path = typer.Option(
        Path("bountyhunt.db"),
        "--db",
        help="Path to SQLite database",
    ),
) -> None:
    """Run recon scan (subfinder → dnsx → httpx).

    Use ``--all`` for the full pipeline: recon → portscan → content crawling
    → secret scanning → nuclei → tech detection.

    By default, nuclei excludes intrusive templates (dos, fuzz).
    Pass ``--include-intrusive`` only if you understand the risks.
    """
    scope = Scope.from_file(scope_file)
    db = Database(db_path)
    targets = [target] if target else scope.targets

    if all_mode:
        _run_all_pipeline(scope, db, targets, rate, severity, include_intrusive, show_full_secrets)
    else:
        _run_recon_only(scope, db, targets)

    rprint(f"\n[green]✓[/green] Results saved to [bold]{db_path}[/bold]")


def _run_recon_only(scope: Scope, db: Database, targets: List[str]) -> None:
    """Run recon pipeline (subfinder → dnsx → httpx)."""
    all_hosts: list[dict] = []
    for t in targets:
        pipeline = ReconPipeline(scope, db)
        hosts = pipeline.run(t)
        all_hosts.extend(hosts)

    if all_hosts:
        ReconPipeline(scope, db).display_results(all_hosts)
    else:
        rprint("[yellow]No hosts found or all out of scope.[/yellow]")


def _run_all_pipeline(
    scope: Scope,
    db: Database,
    targets: List[str],
    rate: int,
    severity: str,
    include_intrusive: bool,
    show_full_secrets: bool,
) -> None:
    """Full pipeline: recon → portscan → content → secrets → nuclei → tech.

    Step 1 — subdomain discovery and host probing (subfinder → dnsx → httpx).
    Step 2 — port scan resolved IPs with naabu, probe non-standard ports.
    Step 3 — content crawling (katana): discover endpoints/JS files.
    Step 4 — secret scanning (regex) on discovered endpoints.
    Step 5 — nuclei vulnerability scan.
    Step 6 — display technology summary.
    """
    all_hosts: list[dict] = []

    # Step 1: recon
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as p:
        p.add_task("Recon: subfinder → dnsx → httpx...", total=None)
        for t in targets:
            pipeline = ReconPipeline(scope, db)
            hosts = pipeline.run(t)
            all_hosts.extend(hosts)

    if not all_hosts:
        rprint("[yellow]No hosts found during recon, skipping remaining steps.[/yellow]")
        ReconPipeline(scope, db).display_results([])
        return

    ReconPipeline(scope, db).display_results(all_hosts)

    # Step 2: port scan + httpx probing
    resolved = [{"domain": h["domain"], "ip": h.get("ip", "")} for h in all_hosts if h.get("ip")]
    port_scan_run_id = db.save_scan_run("portscan", ",".join(targets))
    port_scan = PortScanPipeline(scope, db, rate=rate)
    ports = port_scan.run(resolved, port_scan_run_id)

    if ports:
        rprint(f"[cyan]  → {len(ports)} open ports found, probing with httpx...[/cyan]")
        port_urls = PortScanPipeline.to_urls(ports)
        pipeline = ReconPipeline(scope, db)
        extra_hosts = pipeline._run_httpx(
            [{"domain": u, "ip": ""} for u in port_urls],
            port_scan_run_id,
        )
        pipeline._save_results(extra_hosts, port_scan_run_id)
        all_hosts.extend(extra_hosts)
        if extra_hosts:
            rprint(f"[green]  → {len(extra_hosts)} additional web services found via port probing[/green]")

    # Step 3: content crawling via katana
    content = ContentPipeline(scope, db)
    content_run_id = db.save_scan_run("content", ",".join(targets))
    content_targets = list({h["domain"] for h in all_hosts if scope.can_scan(h["domain"])})
    if ports:
        content_targets.extend(PortScanPipeline.to_urls(ports))

    endpoints = content.run(content_targets, content_run_id)
    if endpoints:
        new_count = sum(1 for e in endpoints if e["new"])
        rprint(f"  [cyan]→ {len(endpoints)} endpoints ({new_count} new) discovered[/cyan]")

    # Step 4: secret scanning on discovered endpoints
    if endpoints:
        secrets_pipeline = SecretsPipeline(db, store_raw=show_full_secrets)
        secrets_run_id = db.save_scan_run("secrets", ",".join(targets))
        secrets_found = secrets_pipeline.run(endpoints, secrets_run_id)
        if secrets_found:
            new_count = sum(1 for s in secrets_found if s["new"])
            rprint(f"  [cyan]→ {len(secrets_found)} potential secrets ({new_count} new)[/cyan]")
            rprint("  [yellow]  ⚠  Review before sharing reports.[/yellow]")
        else:
            rprint("  [cyan]→ secrets: no matches[/cyan]")
    else:
        rprint("  [yellow]  No endpoints to scan for secrets.[/yellow]")

    # Step 5: nuclei
    exclude_tags = None if include_intrusive else ["dos", "fuzz", "intrusive"]
    nuclei = NucleiPipeline(scope, db, severity=severity, exclude_tags=exclude_tags)
    nuclei_run_id = db.save_scan_run("nuclei", ",".join(targets))

    nuclei_targets = list({h["domain"] for h in all_hosts if scope.can_scan(h["domain"])})
    if ports:
        nuclei_targets.extend(PortScanPipeline.to_urls(ports))

    findings = nuclei.run(nuclei_targets, nuclei_run_id)

    if findings:
        counts: dict = {}
        for f in findings:
            sev = (f["severity"] or "unknown").upper()
            counts[sev] = counts.get(sev, 0) + 1
        tag = NucleiPipeline._format_severity_tag(counts)
        new_count = sum(1 for f in findings if f["new"])
        rprint(f"  [cyan]→ {len(findings)} total, {new_count} new findings:[/cyan] {tag}")
        rprint("  [yellow]  ⚠  Manual verification required before reporting.[/yellow]")
    else:
        rprint("  [cyan]→ nuclei: no findings[/cyan]")

    # Step 6: tech summary (reads from DB, no network calls)
    display_tech_table(db)


@app.command()
def report(
    db_path: Path = typer.Option(
        Path("bountyhunt.db"),
        "--db",
        help="Path to SQLite database",
    ),
    output: Path = typer.Option(
        Path("report.md"),
        "--output",
        "-o",
        help="Output file path",
    ),
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="Target domain for diff section",
    ),
    fmt: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Report format (markdown or html)",
    ),
) -> None:
    """Generate a report from scan results.

    Pass ``--target`` to include a "Changes Since Last Scan" diff section
    (requires at least two scan runs for the target).
    """
    db = Database(db_path)
    hosts = db.get_hosts(limit=500)
    scan_runs = db.get_scan_runs(limit=10)
    findings = db.get_findings(limit=500)
    endpoints = db.get_endpoints(limit=500)
    secrets = db.get_secrets(limit=500)

    if not hosts:
        rprint("[yellow]No scan results found in database. Run a scan first.[/yellow]")
        raise typer.Exit(code=1)

    # Compute diff — reuses get_diff_summary() from monitor.py
    diff = None
    if target:
        last_ts = db.get_last_scan_for_target(target)
        if last_ts:
            runs = db.get_scan_runs_for_target(target, limit=2)
            if len(runs) >= 2:
                since_ts = runs[1]["timestamp"]  # second-most-recent
                diff = get_diff_summary(db, target, since_ts, runs[0]["timestamp"])
            else:
                diff = DiffSummary(target=target, scan_timestamp=runs[0]["timestamp"], is_baseline=True)
        else:
            rprint(f"[yellow]No scans found for target: {target}[/yellow]")

    generate_report(
        hosts,
        scan_runs,
        output,
        fmt,
        findings=findings,
        endpoints=endpoints,
        secrets=secrets,
        diff=diff,
    )
    rprint(f"[green]✓[/green] Report generated: [bold]{output}[/bold]")


@app.command()
def monitor(
    scope_file: Path = typer.Argument(
        ...,
        help="Path to scope YAML file",
        exists=True,
    ),
    target: Optional[str] = typer.Option(
        None,
        "--target",
        "-t",
        help="Specific target domain (overrides scope)",
    ),
    rate: int = typer.Option(
        100,
        "--rate",
        "-r",
        help="Packets per second for port scan (naabu)",
    ),
    severity: str = typer.Option(
        "low,medium,high,critical",
        "--severity",
        "-s",
        help="Nuclei severity filter (comma-separated)",
    ),
    include_intrusive: bool = typer.Option(
        False,
        "--include-intrusive",
        help="Enable nuclei templates tagged dos/fuzz/intrusive (unsafe)",
    ),
    show_full_secrets: bool = typer.Option(
        False,
        "--show-full-secrets",
        help="Store raw secret values (exposes credentials — use with caution)",
    ),
    db_path: Path = typer.Option(
        Path("bountyhunt.db"),
        "--db",
        help="Path to SQLite database",
    ),
) -> None:
    """Run full scan and send notifications for new findings.

    Designed for cron/systemd timer integration.  On first run for a
    target, establishes a baseline with no notifications.  Subsequent
    runs diff against the last scan and send a digest to configured
    notification channels (Discord webhook and/or Telegram bot).

    Configuration (environment variables):
      DISCORD_WEBHOOK_URL  — Discord webhook URL
      TELEGRAM_BOT_TOKEN   — Telegram bot token
      TELEGRAM_CHAT_ID     — Telegram chat/group ID
    """
    scope = Scope.from_file(scope_file)
    db = Database(db_path)
    targets = [target] if target else scope.targets

    def _scan_and_save(s: Scope, d: Database, ts: List[str]) -> None:
        _run_all_pipeline(s, d, ts, rate, severity, include_intrusive, show_full_secrets)

    for t in targets:
        rprint(f"\n[bold]Monitoring target:[/bold] {t}")
        results = run_monitor(scope, db, t, _scan_and_save)

        if results.get("baseline"):
            rprint("[green]  ✓ Baseline established — no notifications sent.[/green]")
        elif results:
            successes = [k for k, v in results.items() if v]
            failures = [k for k, v in results.items() if not v]
            if successes:
                rprint(f"[green]  ✓ Notifications sent: {', '.join(successes)}[/green]")
            if failures:
                rprint(f"[red]  ✗ Notification failures: {', '.join(failures)}[/red]")
        else:
            rprint("[cyan]  → No new findings.[/cyan]")
