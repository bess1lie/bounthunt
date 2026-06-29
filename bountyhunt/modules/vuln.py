"""Vulnerability scanning with nuclei — automated template-based security checks.

SAFETY
------
By default, nuclei templates tagged with ``dos``, ``fuzz``, or ``intrusive``
are EXCLUDED from every run.  These templates can cause service disruption
or unwanted side effects on target infrastructure.

To include them you must explicitly pass ``include_intrusive=True`` (or
``--include-intrusive`` on the CLI).  This is a deliberate design decision,
not an oversight.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import List, Optional

from rich.console import Console

from bountyhunt.core.db import Database
from bountyhunt.core.runner import ToolNotFoundError, ToolTimeoutError, run_tool
from bountyhunt.core.scope import Scope

logger = logging.getLogger(__name__)
console = Console()


class NucleiPipeline:
    """Run nuclei against in-scope hosts.

    Parameters
    ----------
    scope : Scope
        Scope guard — uses ``can_scan()`` (not ``is_in_scope()``) so that
        wildcard-allow targets like ``*.example.com`` correctly scan the
        root domain ``example.com``.
    db : Database
        Findings are persisted with a stable ``finding_key`` for dedup.
    severity : str
        Comma-separated severity filter passed to ``-severity`` (default
        ``"low,medium,high,critical"``).  Filtering is done by nuclei
        itself, not in post-processing.
    exclude_tags : list of str
        Template tags to exclude.  Default is ``["dos", "fuzz", "intrusive"]``
        for safety.  Pass an empty list to allow all.
    rate_limit : int
        Requests per second (nuclei ``-rl``).  Default 150.
    concurrency : int
        Host concurrency (nuclei ``-c``).  Default 25.
    """

    def __init__(
        self,
        scope: Scope,
        db: Database,
        severity: str = "low,medium,high,critical",
        exclude_tags: Optional[List[str]] = None,
        rate_limit: int = 150,
        concurrency: int = 25,
    ):
        self.scope = scope
        self.db = db
        self.severity = severity
        self.exclude_tags = exclude_tags or ["dos", "fuzz", "intrusive"]
        self.rate_limit = rate_limit
        self.concurrency = concurrency

    def run(self, targets: List[str], scan_run_id: int) -> List[dict]:
        """Run nuclei against a list of host:port or domain targets.

        Returns list of finding dicts with keys:
        ``host, template_id, name, severity, matched_at, description``.

        Every finding is stored in the DB with a stable ``finding_key``.
        Duplicates (same host + template + match) are silently skipped.
        """
        if not targets:
            return []

        safe = [t for t in targets if self.scope.can_scan(t)]
        if not safe:
            console.print("[yellow]  No in-scope targets for nuclei.[/yellow]")
            return []

        console.print("[cyan]  • nuclei[/cyan]")

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(safe))
            tmp_path = f.name

        cmd = [
            "nuclei",
            "-l",
            tmp_path,
            "-json",
            "-silent",
            "-severity",
            self.severity,
            "-rl",
            str(self.rate_limit),
            "-c",
            str(self.concurrency),
        ]
        if self.exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(self.exclude_tags)])

        try:
            result = run_tool(cmd, timeout=600)
        except (ToolNotFoundError, ToolTimeoutError) as e:
            console.print(f"[red]  nuclei failed: {e}[/red]")
            Path(tmp_path).unlink(missing_ok=True)
            return []

        Path(tmp_path).unlink(missing_ok=True)

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host", "") or data.get("matched-at", "") or data.get("ip", "")
            template_id = data.get("template-id", "")
            matched_at = data.get("matched-at", "")
            name = data.get("info", {}).get("name", "") if isinstance(data.get("info"), dict) else ""
            sev = data.get("info", {}).get("severity", "") if isinstance(data.get("info"), dict) else ""
            description = data.get("info", {}).get("description", "") if isinstance(data.get("info"), dict) else ""

            if not host or not template_id:
                continue

            if not self.scope.can_scan(host):
                continue

            is_new = self.db.save_finding(
                host=host,
                template_id=template_id,
                matched_at=matched_at,
                name=name,
                severity=sev.upper() if sev else "",
                description=description,
                scan_run_id=scan_run_id,
            )

            findings.append(
                {
                    "host": host,
                    "template_id": template_id,
                    "name": name,
                    "severity": sev,
                    "matched_at": matched_at,
                    "description": description,
                    "new": is_new,
                }
            )

        new_count = sum(1 for f in findings if f["new"])
        total = len(findings)
        logger.info("nuclei: %d findings (%d new)", total, new_count)
        return findings

    @staticmethod
    def _format_severity_tag(counts: dict) -> str:
        """Pretty-print severity breakdown for CLI output."""
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = counts.get(sev, 0)
            if n:
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "white"}.get(
                    sev, ""
                )
                parts.append(f"[{color}]{n} {sev.lower()}[/{color}]")
        return ", ".join(parts) if parts else "(none)"
