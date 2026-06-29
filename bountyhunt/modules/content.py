"""Content crawling with katana — discovers endpoints (URLs, paths, JS files).

Scope guard is applied per discovered URL, not just at the input level.
If katana follows a cross-domain redirect, the resulting URL is checked
against ``can_scan()`` before being stored.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import List
from urllib.parse import urlparse

from rich.console import Console

from bountyhunt.core.db import Database
from bountyhunt.core.runner import ToolNotFoundError, ToolTimeoutError, run_tool
from bountyhunt.core.scope import Scope

logger = logging.getLogger(__name__)
console = Console()


class ContentPipeline:
    """Crawl discovered hosts with katana and store discovered endpoints.

    Parameters
    ----------
    scope : Scope
        Scope guard — every discovered URL's host is checked with
        ``can_scan()`` before persisting.
    db : Database
        Endpoints are stored with dedup on ``url``.
    depth : int
        Crawl depth for katana (``-d``).  Default 2.
    rate_limit : int
        Requests per second (katana ``-rl``).  Default 50.
    """

    def __init__(
        self,
        scope: Scope,
        db: Database,
        depth: int = 2,
        rate_limit: int = 50,
    ):
        self.scope = scope
        self.db = db
        self.depth = depth
        self.rate_limit = rate_limit

    def run(self, targets: List[str], scan_run_id: int) -> List[dict]:
        """Run katana against a list of URLs / domains.

        Returns list of endpoint dicts with keys:
        ``url, host, status_code, content_length, content_type``.
        """
        if not targets:
            return []

        safe = [t for t in targets if self.scope.can_scan(self._extract_host(t))]
        if not safe:
            console.print("[yellow]  No in-scope targets for katana.[/yellow]")
            return []

        console.print("[cyan]  • katana[/cyan]")

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(safe))
            tmp_path = f.name

        cmd = [
            "katana",
            "-list",
            tmp_path,
            "-json",
            "-silent",
            "-d",
            str(self.depth),
            "-rl",
            str(self.rate_limit),
            "-jc",  # crawl JS files for endpoints
        ]

        try:
            result = run_tool(cmd, timeout=600)
        except (ToolNotFoundError, ToolTimeoutError) as e:
            console.print(f"[red]  katana failed: {e}[/red]")
            Path(tmp_path).unlink(missing_ok=True)
            return []

        Path(tmp_path).unlink(missing_ok=True)

        endpoints = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = data.get("url", "")
            if not url:
                continue

            host = self._extract_host(url)
            if not host or not self.scope.can_scan(host):
                continue

            status_code = data.get("status-code") or data.get("status_code")
            content_length = data.get("content-length") or data.get("content_length")
            content_type = data.get("content-type", "") or data.get("content_type", "")
            if isinstance(content_type, list):
                content_type = ",".join(content_type)

            is_new = self.db.save_endpoint(
                url=url,
                host=host,
                status_code=status_code,
                content_length=content_length,
                content_type=content_type,
                scan_run_id=scan_run_id,
            )

            endpoints.append(
                {
                    "url": url,
                    "host": host,
                    "status_code": status_code,
                    "content_length": content_length,
                    "content_type": content_type,
                    "new": is_new,
                }
            )

        new_count = sum(1 for e in endpoints if e["new"])
        logger.info("katana: %d endpoints (%d new)", len(endpoints), new_count)
        return endpoints

    @staticmethod
    def _extract_host(url: str) -> str:
        """Extract hostname from a URL or return as-is if already a host."""
        if "://" in url:
            return urlparse(url).hostname or url
        # Already a hostname, strip port if present
        return url.split(":")[0]
