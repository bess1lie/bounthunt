"""Port scanning with naabu — finds open ports, feeds results into httpx.

Open ports on non-standard ports (8080, 8443, 9000, etc.) are often
overlooked but may host interesting web services.  The pipeline caller
is responsible for feeding discovered ``host:port`` pairs back into
httpx — see the TODO in ``cli.py _run_all_pipeline``.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import List

from rich.console import Console

from bountyhunt.core.db import Database
from bountyhunt.core.runner import ToolNotFoundError, ToolTimeoutError, run_tool
from bountyhunt.core.scope import Scope

logger = logging.getLogger(__name__)
console = Console()


class PortScanPipeline:
    """Run naabu on resolved hosts to discover open ports.

    Rate-limit defaults to 100 pkts/s; callers can override.  This is
    intentionally a parameter, not a constant, so it can later be
    sourced from ``scope.yaml`` per-program.
    """

    def __init__(self, scope: Scope, db: Database, rate: int = 100):
        self.scope = scope
        self.db = db
        self.rate = rate

    def run(self, resolved: List[dict], scan_run_id: int) -> List[dict]:
        """Run naabu on resolved (domain, ip) pairs.

        Returns list of ``{"host", "port", "protocol"}`` dicts.
        """
        if not resolved:
            return []

        # Filter to in-scope domains only (defensive; caller should already do this)
        resolved = [e for e in resolved if self.scope.can_scan(e["domain"])]
        if not resolved:
            console.print("[yellow]  No in-scope targets to scan.[/yellow]")
            return []

        console.print("[cyan]  • naabu[/cyan]")

        ips = sorted({e["ip"] for e in resolved if e.get("ip")})
        if not ips:
            console.print("[yellow]  No IPs to scan.[/yellow]")
            return []

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(ips))
            tmp_path = f.name

        try:
            result = run_tool(
                [
                    "naabu",
                    "-list",
                    tmp_path,
                    "-json",
                    "-silent",
                    "-top-ports",
                    "1000",
                    "-rate",
                    str(self.rate),
                ],
                timeout=300,
            )
        except (ToolNotFoundError, ToolTimeoutError) as e:
            console.print(f"[red]  naabu failed: {e}[/red]")
            Path(tmp_path).unlink(missing_ok=True)
            return []

        Path(tmp_path).unlink(missing_ok=True)

        ports = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host", "") or data.get("ip", "")
            port = data.get("port")
            protocol = data.get("protocol", "tcp")

            if not host or not port:
                continue

            # Even though we scanned IPs, check against the original domain.
            # Build a reverse lookup from the filtered resolved list.
            domain = next((e["domain"] for e in resolved if e["ip"] == host), host)
            if not self.scope.can_scan(domain):
                continue

            ports.append({"host": host, "port": port, "protocol": protocol})
            self.db.upsert_port(host, port, protocol, scan_run_id=scan_run_id)

        logger.info("naabu: %d open ports found", len(ports))
        return ports

    @staticmethod
    def to_urls(ports: List[dict]) -> List[str]:
        """Convert discovered ports to URLs for httpx probing.

        Used by ``scan --all`` to feed non-standard ports back into httpx.
        """
        urls = []
        for p in ports:
            scheme = "https" if p["port"] in (443, 8443) else "http"
            urls.append(f"{scheme}://{p['host']}:{p['port']}")
        return urls
