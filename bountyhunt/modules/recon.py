from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table

from bountyhunt.core.db import Database
from bountyhunt.core.runner import ToolNotFoundError, ToolTimeoutError, run_tool
from bountyhunt.core.scope import Scope

logger = logging.getLogger(__name__)
console = Console()


class ReconPipeline:
    """subfinder → dnsx → httpx pipeline for subdomain discovery and host probing."""

    def __init__(self, scope: Scope, db: Database):
        self.scope = scope
        self.db = db

    def run(self, domain: str) -> List[dict]:
        if not self.scope.can_scan(domain):
            console.print(f"[red]Domain '{domain}' is not a valid scan target for this scope. Skipping.[/red]")
            return []

        scan_run_id = self.db.save_scan_run("recon", domain)
        console.print(f"[bold green]→ Starting recon for:[/bold green] {domain}")

        subdomains = self._run_subfinder(domain)
        if not subdomains:
            console.print("[yellow]No subdomains found.[/yellow]")
            return []

        resolved = self._run_dnsx(subdomains)
        if not resolved:
            console.print("[yellow]No subdomains resolved.[/yellow]")
            return []

        hosts = self._run_httpx(resolved, scan_run_id)
        self._save_results(hosts, scan_run_id)
        return hosts

    @staticmethod
    def _parse_json_lines(stdout: str) -> List[dict]:
        """Parse newline-delimited JSON output from a tool."""
        results = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON line: %s", line[:80])
        return results

    def _run_subfinder(self, domain: str) -> List[str]:
        console.print("[cyan]  • subfinder[/cyan]")
        try:
            result = run_tool(["subfinder", "-d", domain, "-json", "-silent"], timeout=120)
        except (ToolNotFoundError, ToolTimeoutError) as e:
            console.print(f"[red]  subfinder failed: {e}[/red]")
            return []

        entries = self._parse_json_lines(result.stdout)
        subdomains = [e.get("host", "") for e in entries if e.get("host")]
        in_scope = [s for s in subdomains if self.scope.is_in_scope(s)]
        logger.info("subfinder: %d found, %d in scope", len(subdomains), len(in_scope))
        return in_scope

    def _run_dnsx(self, subdomains: List[str]) -> List[dict]:
        console.print("[cyan]  • dnsx[/cyan]")
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(subdomains))
            tmp_path = f.name

        try:
            result = run_tool(["dnsx", "-l", tmp_path, "-json", "-silent"], timeout=120)
        except (ToolNotFoundError, ToolTimeoutError) as e:
            console.print(f"[red]  dnsx failed: {e}[/red]")
            Path(tmp_path).unlink(missing_ok=True)
            return []

        Path(tmp_path).unlink(missing_ok=True)

        entries = self._parse_json_lines(result.stdout)
        resolved = []
        for e in entries:
            domain = e.get("host", "")
            if not domain:
                continue
            ips = e.get("a", [])
            ip = ips[0] if isinstance(ips, list) and ips else (ips if isinstance(ips, str) else None)
            resolved.append({"domain": domain, "ip": ip})

        logger.info("dnsx: %d resolved", len(resolved))
        return resolved

    def _run_httpx(self, resolved: List[dict], scan_run_id: int) -> List[dict]:
        console.print("[cyan]  • httpx[/cyan]")
        input_lines = []
        for entry in resolved:
            d = entry["domain"]
            if d.startswith(("http://", "https://")):
                input_lines.append(d)
            else:
                input_lines.append(f"http://{d}")

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(input_lines))
            tmp_path = f.name

        try:
            result = run_tool(
                [
                    "httpx",
                    "-l",
                    tmp_path,
                    "-silent",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-content-length",
                    "-web-server",
                    "-json",
                    "-timeout",
                    "10",
                ],
                timeout=180,
            )
        except (ToolNotFoundError, ToolTimeoutError) as e:
            console.print(f"[red]  httpx failed: {e}[/red]")
            Path(tmp_path).unlink(missing_ok=True)
            return []

        Path(tmp_path).unlink(missing_ok=True)

        hosts = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            domain = data.get("host", "") or self._extract_domain(data.get("url", ""))
            if not domain or not self.scope.is_in_scope(domain):
                continue

            hosts.append(
                {
                    "domain": domain,
                    "ip": data.get("a", [None])[0] if isinstance(data.get("a"), list) else data.get("a"),
                    "status_code": data.get("status_code"),
                    "title": data.get("title"),
                    "tech": data.get("tech", []),
                    "content_length": data.get("content_length"),
                    "webserver": data.get("webserver"),
                    "scan_run_id": scan_run_id,
                }
            )

        logger.info("httpx: %d live hosts", len(hosts))
        return hosts

    def _save_results(self, hosts: List[dict], scan_run_id: int) -> None:
        for host in hosts:
            self.db.upsert_host(
                domain=host["domain"],
                ip=host.get("ip"),
                status_code=host.get("status_code"),
                title=host.get("title"),
                tech=host.get("tech"),
                content_length=host.get("content_length"),
                webserver=host.get("webserver"),
                scan_run_id=scan_run_id,
            )

    @staticmethod
    def _extract_domain(url: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.netloc or parsed.path

    def display_results(self, hosts: List[dict]) -> None:
        if not hosts:
            console.print("[yellow]No results to display.[/yellow]")
            return

        table = Table(title="Live Hosts", header_style="bold cyan")
        table.add_column("Domain", style="cyan")
        table.add_column("IP")
        table.add_column("Status")
        table.add_column("Title")
        table.add_column("Tech")
        table.add_column("Web Server")

        for h in hosts:
            tech_str = ", ".join(h.get("tech", []) or [])[:30] if h.get("tech") else ""
            table.add_row(
                h.get("domain", ""),
                h.get("ip", "") or "",
                str(h.get("status_code", "") or ""),
                (h.get("title", "") or "")[:40],
                tech_str,
                h.get("webserver", "") or "",
            )

        console.print(table)
