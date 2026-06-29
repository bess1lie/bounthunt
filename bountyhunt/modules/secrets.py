"""Secret discovery — regex patterns applied to crawled content.

SAFETY
------
Secrets are **redacted by default** before being stored in the database or
displayed in reports.  The full plaintext value is only persisted when
``--show-full-secrets`` is explicitly passed on the CLI, accompanied by a
warning.

This prevents accidental leakage of credentials via committed reports,
database files, or screenshots.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List

from rich.console import Console

from bountyhunt.core.db import Database
from bountyhunt.core.runner import ToolNotFoundError, ToolTimeoutError, run_tool

logger = logging.getLogger(__name__)
console = Console()


# Common secret patterns used in bug bounty recon.
# Keys are pattern_type identifiers used in the DB and redaction logic.
SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "aws": re.compile(r"(?i)(?:AKIA[0-9A-Z]{16})"),
    "jwt": re.compile(r"(?i)eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    "google_api": re.compile(r"(?i)AIza[0-9A-Za-z\-_]{35}"),
    "github_token": re.compile(r"(?i)(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}"),
    "slack_token": re.compile(r"(?i)xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    "generic_token": re.compile(
        r"(?i)(?:api[-_]?key|api[-_]?secret|access[-_]?token|"
        r"secret[-_]?key|auth[-_]?token)\s*[=:]\s*['\"]?([0-9a-zA-Z_\-]{16,})"
    ),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "jira_token": re.compile(r"(?i)ATATT3x[A-Za-z0-9_\-]{60,}"),
}


class SecretsPipeline:
    """Scan discovered endpoints for hardcoded secrets using regex patterns.

    To scan the actual content of discovered endpoints, this pipeline
    fetches each endpoint via httpx (or reads previously stored content)
    and runs regex against the response body.
    """

    def __init__(
        self,
        db: Database,
        store_raw: bool = False,
        rate_limit: int = 50,
    ):
        self.db = db
        self.store_raw = store_raw
        self.rate_limit = rate_limit

    def run(self, endpoints: List[dict], scan_run_id: int) -> List[dict]:
        """Scan a list of endpoint dicts for secrets.

        Each endpoint should have at minimum a ``url`` key.  The endpoint
        response body is fetched via httpx and scanned with all configured
        regex patterns.

        Returns list of secret dicts::
        ``host, url, pattern_type, redacted, raw_value, new``.
        """
        if not endpoints:
            return []

        # Fetch bodies via httpx
        bodies = self._fetch_bodies([e["url"] for e in endpoints], scan_run_id)

        found = []
        for ep in endpoints:
            body = bodies.get(ep["url"], "")
            if not body:
                continue
            host = ep.get("host", self._extract_host(ep["url"]))
            matches = self._scan_body(body)
            for pattern_type, values in matches.items():
                for val in values:
                    if not val.strip():
                        continue
                    is_new = self.db.save_secret(
                        host=host,
                        url=ep["url"],
                        pattern_type=pattern_type,
                        raw_value=val.strip(),
                        store_raw=self.store_raw,
                        scan_run_id=scan_run_id,
                    )
                    found.append(
                        {
                            "host": host,
                            "url": ep["url"],
                            "pattern_type": pattern_type,
                            "redacted": self.db.redact_secret(val.strip(), pattern_type),
                            "new": is_new,
                        }
                    )

        new_count = sum(1 for s in found if s["new"])
        logger.info("secrets: %d findings (%d new)", len(found), new_count)
        return found

    def _fetch_bodies(self, urls: List[str], scan_run_id: int) -> Dict[str, str]:
        """Fetch endpoint response bodies via httpx.

        Returns dict of ``{url: body_text}``.
        """
        if not urls:
            return {}
        import json
        import tempfile
        from pathlib import Path

        console.print("[cyan]  • httpx (content fetch)[/cyan]")

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("\n".join(urls))
            tmp_path = f.name

        try:
            result = run_tool(
                [
                    "httpx",
                    "-l",
                    tmp_path,
                    "-silent",
                    "-status-code",
                    "-response-body",
                    "-json",
                    "-timeout",
                    "10",
                ],
                timeout=300,
            )
        except (ToolNotFoundError, ToolTimeoutError) as e:
            console.print(f"[red]  httpx content fetch failed: {e}[/red]")
            Path(tmp_path).unlink(missing_ok=True)
            return {}

        Path(tmp_path).unlink(missing_ok=True)

        bodies = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = data.get("url", "") or data.get("host", "")
            body = data.get("body", "") or data.get("response_body", "")
            bodies[url] = body

        return bodies

    def _scan_body(self, body: str) -> Dict[str, List[str]]:
        """Run all regex patterns against a response body.

        Returns dict of ``{pattern_type: [matched_values]}`` with dedup
        within each pattern type.
        """
        results: Dict[str, List[str]] = {}
        for ptype, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(body)
            if matches:
                seen = set()
                unique = []
                for m in matches:
                    if isinstance(m, tuple):
                        m = m[0]
                    if m not in seen:
                        seen.add(m)
                        unique.append(m)
                results[ptype] = unique
        return results

    @staticmethod
    def _extract_host(url: str) -> str:
        from urllib.parse import urlparse

        if "://" in url:
            return urlparse(url).hostname or url
        return url.split(":")[0]
