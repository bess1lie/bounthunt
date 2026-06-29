"""Notification dispatch — sends digest messages to Telegram and/or Discord.

SAFETY
------
This module **never** accepts ``raw_value`` for secrets in its public API.
The ``DiffSummary`` dataclass only contains a ``redacted`` field for secret
entries.  Even if ``--show-full-secrets`` was enabled during data collection,
the raw values are stripped by ``monitor.py`` before calling any function in
this module.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


@dataclass
class DiffSummary:
    """Summary of new items discovered since the last scan run.

    The ``secrets`` list MUST only contain dicts with a ``redacted`` key.
    The ``raw_value`` field — even if present in the database — is never
    passed to this dataclass (enforced by ``monitor.py``).
    """

    target: str
    scan_timestamp: str
    is_baseline: bool = False

    hosts: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.hosts) + len(self.findings) + len(self.endpoints) + len(self.secrets) + len(self.ports)

    @property
    def has_items(self) -> bool:
        return self.total > 0 and not self.is_baseline


def format_digest(diffs: DiffSummary) -> str:
    """Format a human-readable digest message for webhook dispatch.

    This function is the ONLY place where message formatting happens.
    It receives already-redacted data — no access to ``raw_value``.
    """
    if diffs.is_baseline:
        return (
            f"🔍 *bountyhunt — Baseline Established*\n"
            f"Target: `{diffs.target}`\n"
            f"First scan complete. No notifications sent — "
            f"baseline saved for future comparison."
        )

    if not diffs.has_items:
        return (
            f"✅ *bountyhunt — No Changes*\n"
            f"Target: `{diffs.target}`\n"
            f"Scan {diffs.scan_timestamp}: no new findings detected."
        )

    lines = ["🔍 *bountyhunt — Scan Digest*", f"Target: `{diffs.target}`", ""]

    sections = []

    if diffs.hosts:
        hosts_list = "\n".join(
            f"  • `{h.get('domain', h.get('host', '?'))}` ({h.get('status_code', '')}) {h.get('title', '')}"
            for h in diffs.hosts[:10]
        )
        suffix = f" …and {len(diffs.hosts) - 10} more" if len(diffs.hosts) > 10 else ""
        sections.append(f"*🌐 Hosts — {len(diffs.hosts)} new*\n{hosts_list}{suffix}")

    if diffs.ports:
        ports_list = "\n".join(f"  • `{p['host']}:{p['port']}` ({p.get('protocol', 'tcp')})" for p in diffs.ports[:10])
        suffix = f" …and {len(diffs.ports) - 10} more" if len(diffs.ports) > 10 else ""
        sections.append(f"*🔌 Ports — {len(diffs.ports)} new*\n{ports_list}{suffix}")

    if diffs.endpoints:
        ep_list = "\n".join(f"  • `{e['url']}` ({e.get('status_code', '')})" for e in diffs.endpoints[:10])
        suffix = f" …and {len(diffs.endpoints) - 10} more" if len(diffs.endpoints) > 10 else ""
        sections.append(f"*📁 Endpoints — {len(diffs.endpoints)} new*\n{ep_list}{suffix}")

    if diffs.findings:
        f_list = "\n".join(
            f"  • [{f.get('severity', '?')}] {f.get('name', f.get('template_id', '?'))} — `{f['host']}`"
            for f in diffs.findings[:10]
        )
        suffix = f" …and {len(diffs.findings) - 10} more" if len(diffs.findings) > 10 else ""
        sections.append(f"*⚠️  Potential Findings — {len(diffs.findings)} new*\n{f_list}{suffix}")

    if diffs.secrets:
        s_list = "\n".join(f"  • [{s['pattern_type']}] `{s['host']}` — ``{s['redacted']}``" for s in diffs.secrets[:10])
        suffix = f" …and {len(diffs.secrets) - 10} more" if len(diffs.secrets) > 10 else ""
        sections.append(f"*🔑 Secrets — {len(diffs.secrets)} new (redacted)*\n{s_list}{suffix}")

    lines.append("\n\n".join(sections))
    lines.append("")
    lines.append("⚠️  *Manual verification required before reporting findings.*")
    return "\n".join(lines)


def send_digest(diffs: DiffSummary) -> Dict[str, bool]:
    """Send digest to all configured notification channels.

    Returns dict of ``{channel_name: success}``.

    Redaction boundary: this function only receives the ``DiffSummary``
    dataclass, which contains ``redacted`` (not ``raw_value``) for secrets.
    """
    results: Dict[str, bool] = {}

    text = format_digest(diffs)

    discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if discord_url:
        results["discord"] = _send_discord(discord_url, text)

    telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    telegram_chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if telegram_token and telegram_chat:
        results["telegram"] = _send_telegram(telegram_token, telegram_chat, text)

    if not results:
        logger.info("No notification channels configured (set DISCORD_WEBHOOK_URL or TELEGRAM_*)")

    return results


def _send_discord(webhook_url: str, text: str) -> bool:
    """Send a message to a Discord webhook."""
    payload = json.dumps({"content": text[:2000]}).encode()
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15)
        logger.info("Discord notification sent")
        return True
    except Exception as e:
        logger.error("Discord notification failed: %s", e)
        return False


def _send_telegram(token: str, chat_id: str, text: str) -> bool:
    """Send a message via Telegram Bot API."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    # Telegram markdown uses different escaping — use plain text
    payload = json.dumps(
        {
            "chat_id": chat_id,
            "text": text[:4096],
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
    ).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15)
        logger.info("Telegram notification sent")
        return True
    except Exception as e:
        logger.error("Telegram notification failed: %s", e)
        return False
