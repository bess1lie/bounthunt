"""Technology detection — processes httpx tech data already stored in the DB.

This module does NOT make any network calls.  Tech data is collected once
during the recon pipeline (httpx -tech-detect).  This module reads it from
the database, enriches it, and formats it for reports.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table

from bountyhunt.core.db import Database

console = Console()


def get_tech_summary(db: Database) -> List[Dict[str, Any]]:
    """Aggregate technology data from stored hosts.

    Returns deduplicated list of (domain, tech_list) pairs.
    """
    hosts = db.get_hosts(limit=500)
    results = []
    seen = set()
    for h in hosts:
        domain = h.get("domain", "")
        if domain in seen:
            continue
        seen.add(domain)
        tech_raw = h.get("tech")
        tech_list = []
        if tech_raw:
            try:
                tech_list = json.loads(tech_raw) if isinstance(tech_raw, str) else (tech_raw or [])
            except (json.JSONDecodeError, TypeError):
                tech_list = []
        results.append({"domain": domain, "tech": tech_list})
    return results


def get_tech_by_category(db: Database) -> Dict[str, List[str]]:
    """Group technologies by type (placeholder for future enrichment)."""
    summary = get_tech_summary(db)
    tech_map: Dict[str, set] = {}
    for entry in summary:
        for t in entry["tech"]:
            t = t.strip()
            if t not in tech_map:
                tech_map[t] = set()
            tech_map[t].add(entry["domain"])
    return {k: sorted(v) for k, v in tech_map.items()}


def display_tech_table(db: Database) -> None:
    """Print a Rich table of host technologies."""
    summary = get_tech_summary(db)
    table = Table(title="Technology Detection", header_style="bold cyan")
    table.add_column("Domain", style="cyan")
    table.add_column("Technologies")

    for entry in summary:
        tech_str = ", ".join(entry["tech"]) if entry["tech"] else "—"
        table.add_row(entry["domain"], tech_str)

    console.print(table)
