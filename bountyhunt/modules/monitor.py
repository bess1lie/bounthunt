"""Monitor — diff engine for repeated scan runs with notification dispatch.

First-run Behaviour
-------------------
If no previous scan run exists for the target, the scan runs normally and
all results are saved as a *baseline*.  No notifications are sent, because
every finding would be "new" relative to an empty database — this prevents
an initial flood of alerts.
"""

from __future__ import annotations

import logging
from typing import Dict

from rich.console import Console

from bountyhunt.core.db import Database
from bountyhunt.core.scope import Scope
from bountyhunt.modules.notify import DiffSummary, send_digest

logger = logging.getLogger(__name__)
console = Console()


def get_diff_summary(
    db: Database,
    target: str,
    since_timestamp: str,
    scan_timestamp: str,
) -> DiffSummary:
    """Compute a DiffSummary from DB data since a given timestamp.

    This is the **single source of truth** for diff logic — used by both
    ``monitor.py`` (notification dispatch) and ``report/render.py``
    (static report diff section).

    The ``raw_value`` field is stripped from secrets before building
    the ``DiffSummary``, enforcing the redaction boundary.
    """
    hosts = db.get_hosts_for_target_since(target, since_timestamp)
    ports = db.get_ports_for_target_since(target, since_timestamp)
    findings = db.get_findings_for_target_since(target, since_timestamp)

    secrets_raw = db.get_secrets_for_target_since(target, since_timestamp)
    secrets = [{k: v for k, v in s.items() if k != "raw_value"} for s in secrets_raw]

    endpoints = db.get_endpoints_for_target_since(target, since_timestamp)

    return DiffSummary(
        target=target,
        scan_timestamp=scan_timestamp,
        hosts=hosts,
        findings=findings,
        endpoints=endpoints,
        secrets=secrets,
        ports=ports,
    )


def run_monitor(
    scope: Scope,
    db: Database,
    target: str,
    scan_fn,
) -> Dict[str, bool]:
    """Run a full scan, compute diff, and optionally notify.

    Parameters
    ----------
    scope : Scope
        Scope guard passed through to the scan pipeline.
    db : Database
        Persistence layer with all scan results.
    target : str
        Single target domain to monitor.
    scan_fn : callable
        A callable that runs ``scan --all`` for this target.  It is
        expected to accept ``(scope, db, targets)`` and return nothing.
        After it returns, the DB contains the latest scan results.

    Returns
    -------
    dict
        A mapping of ``{channel: success_bool}`` from ``send_digest``,
        or ``{"baseline": True}`` if this was the first run.

    Architecture notes
    ------------------
    - ``raw_value`` is stripped from secrets before building ``DiffSummary``,
      enforcing the redaction boundary in ``notify.py``.
    - Batching: all new items are grouped by type into a single digest message.
    """
    last_scan_ts = db.get_last_scan_for_target(target)
    is_baseline = last_scan_ts is None

    scan_fn(scope, db, [target])

    current_scan_ts = db.get_last_scan_for_target(target)
    if not current_scan_ts:
        logger.warning("monitor: scan completed but no scan_run found")
        return {}

    if is_baseline:
        db.save_scan_run("monitor", target, summary="baseline")
        diffs = DiffSummary(
            target=target,
            scan_timestamp=current_scan_ts,
            is_baseline=True,
        )
        notify_results = send_digest(diffs)
        notify_results["baseline"] = True
        return notify_results

    diffs = get_diff_summary(db, target, last_scan_ts, current_scan_ts)
    db.save_scan_run(
        "monitor",
        target,
        summary=f"{len(diffs.hosts)}h/{len(diffs.findings)}f/{len(diffs.secrets)}s",
    )

    return send_digest(diffs)
