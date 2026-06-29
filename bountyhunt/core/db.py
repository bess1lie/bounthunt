from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class Database:
    """SQLite storage — persists scan results and enables diff comparisons."""

    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'completed',
                summary TEXT
            );

            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                ip TEXT,
                status_code INTEGER,
                title TEXT,
                tech TEXT,
                content_length INTEGER,
                webserver TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                scan_run_id INTEGER,
                FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id),
                UNIQUE(domain, ip)
            );

            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                scan_run_id INTEGER,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id),
                UNIQUE(host, port)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                template_id TEXT NOT NULL,
                name TEXT,
                severity TEXT,
                matched_at TEXT,
                description TEXT,
                scan_run_id INTEGER,
                finding_key TEXT NOT NULL UNIQUE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
            );

            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                host TEXT NOT NULL,
                status_code INTEGER,
                content_length INTEGER,
                content_type TEXT,
                scan_run_id INTEGER,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                url TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                redacted TEXT NOT NULL,
                raw_value TEXT,
                scan_run_id INTEGER,
                finding_key TEXT NOT NULL UNIQUE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
            );

            CREATE INDEX IF NOT EXISTS idx_hosts_domain ON hosts(domain);
            CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);
            CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host);
            CREATE INDEX IF NOT EXISTS idx_findings_key ON findings(finding_key);
            CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host);
            CREATE INDEX IF NOT EXISTS idx_secrets_key ON secrets(finding_key);
        """)
        self.conn.commit()

    def save_scan_run(self, module: str, target: str, status: str = "completed", summary: str | None = None) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.execute(
            "INSERT INTO scan_runs (timestamp, module, target, status, summary) VALUES (?, ?, ?, ?, ?)",
            (now, module, target, status, summary),
        )
        self.conn.commit()
        return cursor.lastrowid

    def upsert_host(
        self,
        domain: str,
        ip: str | None = None,
        status_code: int | None = None,
        title: str | None = None,
        tech: List[str] | None = None,
        content_length: int | None = None,
        webserver: str | None = None,
        scan_run_id: int | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        tech_json = json.dumps(tech) if tech else None

        existing = self.conn.execute(
            "SELECT id FROM hosts WHERE domain = ? AND (ip = ? OR (ip IS NULL AND ? IS NULL))",
            (domain, ip, ip),
        ).fetchone()

        if existing:
            self.conn.execute(
                """UPDATE hosts SET status_code = ?, title = ?, tech = ?,
                   content_length = ?, webserver = ?, last_seen = ?, scan_run_id = ?
                   WHERE id = ?""",
                (status_code, title, tech_json, content_length, webserver, now, scan_run_id, existing["id"]),
            )
        else:
            self.conn.execute(
                "INSERT INTO hosts (domain, ip, status_code, title, tech, content_length, "
                "webserver, first_seen, last_seen, scan_run_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (domain, ip, status_code, title, tech_json, content_length, webserver, now, now, scan_run_id),
            )
        self.conn.commit()

    def get_hosts(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM hosts ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_hosts_by_domain(self, domain: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM hosts WHERE domain LIKE ? ORDER BY last_seen DESC",
            (f"%{domain}%",),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_scan_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM scan_runs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_hosts_since(self, timestamp: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM hosts WHERE first_seen > ? ORDER BY first_seen DESC", (timestamp,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_hosts_by_scan_run_id(self, scan_run_id: int) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM hosts WHERE scan_run_id = ? ORDER BY domain", (scan_run_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_scan_runs_for_target(self, target: str, limit: int = 10) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM scan_runs WHERE target = ? ORDER BY timestamp DESC LIMIT ?",
            (target, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_hosts_for_target_since(self, target: str, timestamp: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT h.* FROM hosts h
               JOIN scan_runs s ON h.scan_run_id = s.id
               WHERE s.target = ? AND h.first_seen > ?
               ORDER BY h.first_seen DESC""",
            (target, timestamp),
        ).fetchall()
        return [dict(r) for r in rows]

    def upsert_port(self, host: str, port: int, protocol: str | None = None, scan_run_id: int | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        existing = self.conn.execute("SELECT id FROM ports WHERE host = ? AND port = ?", (host, port)).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE ports SET last_seen = ?, protocol = ?, scan_run_id = ? WHERE id = ?",
                (now, protocol, scan_run_id, existing["id"]),
            )
        else:
            self.conn.execute(
                "INSERT INTO ports (host, port, protocol, scan_run_id, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (host, port, protocol, scan_run_id, now, now),
            )
        self.conn.commit()

    def get_ports(self, limit: int = 200) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM ports ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_ports_by_host(self, host: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM ports WHERE host = ? ORDER BY port", (host,)).fetchall()
        return [dict(r) for r in rows]

    def get_ports_by_scan_run_id(self, scan_run_id: int) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM ports WHERE scan_run_id = ? ORDER BY host, port", (scan_run_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_ports_for_target_since(self, target: str, timestamp: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT p.* FROM ports p
               JOIN scan_runs s ON p.scan_run_id = s.id
               WHERE s.target = ? AND p.first_seen > ?
               ORDER BY p.first_seen DESC""",
            (target, timestamp),
        ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _make_finding_key(host: str, template_id: str, matched_at: str) -> str:
        raw = f"{host}::{template_id}::{matched_at}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def save_finding(
        self,
        host: str,
        template_id: str,
        matched_at: str,
        name: str | None = None,
        severity: str | None = None,
        description: str | None = None,
        scan_run_id: int | None = None,
    ) -> bool:
        """Insert or update a finding. Returns True if new, False if already known."""
        finding_key = self._make_finding_key(host, template_id, matched_at)
        now = datetime.now(timezone.utc).isoformat()

        existing = self.conn.execute("SELECT id FROM findings WHERE finding_key = ?", (finding_key,)).fetchone()

        if existing:
            self.conn.execute(
                "UPDATE findings SET last_seen = ?, severity = ?, name = ?, "
                "description = ?, scan_run_id = ? WHERE id = ?",
                (now, severity, name, description, scan_run_id, existing["id"]),
            )
            self.conn.commit()
            return False

        self.conn.execute(
            "INSERT INTO findings (host, template_id, name, severity, matched_at, "
            "description, scan_run_id, finding_key, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (host, template_id, name, severity, matched_at, description, scan_run_id, finding_key, now, now),
        )
        self.conn.commit()
        return True

    def get_findings(self, limit: int = 200) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM findings ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY last_seen DESC",
            (severity.upper(),),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_findings_by_scan_run_id(self, scan_run_id: int) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE scan_run_id = ? ORDER BY severity, host",
            (scan_run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def is_known_finding(self, host: str, template_id: str, matched_at: str) -> bool:
        """Check if a finding was already seen in any previous scan run."""
        finding_key = self._make_finding_key(host, template_id, matched_at)
        row = self.conn.execute("SELECT 1 FROM findings WHERE finding_key = ?", (finding_key,)).fetchone()
        return row is not None

    def get_new_findings_since(self, timestamp: str) -> List[Dict[str, Any]]:
        """Findings first seen after a given timestamp (for diff/monitor)."""
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE first_seen > ? ORDER BY first_seen DESC",
            (timestamp,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_findings_for_target_since(self, target: str, timestamp: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT f.* FROM findings f
               JOIN scan_runs s ON f.scan_run_id = s.id
               WHERE s.target = ? AND f.first_seen > ?
               ORDER BY f.first_seen DESC""",
            (target, timestamp),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_endpoints_for_target_since(self, target: str, timestamp: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT e.* FROM endpoints e
               JOIN scan_runs s ON e.scan_run_id = s.id
               WHERE s.target = ? AND e.first_seen > ?
               ORDER BY e.first_seen DESC""",
            (target, timestamp),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_secrets_for_target_since(self, target: str, timestamp: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT r.* FROM secrets r
               JOIN scan_runs s ON r.scan_run_id = s.id
               WHERE s.target = ? AND r.first_seen > ?
               ORDER BY r.first_seen DESC""",
            (target, timestamp),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_last_scan_for_target(self, target: str) -> str | None:
        """Return timestamp of the most recent scan run for a target.

        Returns ``None`` if no previous scan exists (first-run detection
        for monitor baseline).
        """
        row = self.conn.execute(
            "SELECT timestamp FROM scan_runs WHERE target = ? ORDER BY timestamp DESC LIMIT 1",
            (target,),
        ).fetchone()
        return row["timestamp"] if row else None

    @staticmethod
    def redact_secret(value: str, pattern_type: str = "generic") -> str:
        """Return a redacted version of a secret for safe storage and display.

        Rules per pattern type:
        - ``aws``: show first 4 + ``****`` + last 4 (e.g. ``AKIA****ABCD``)
        - ``jwt``: show header + ``.***.***``
        - ``generic``: first 3 + ``****`` + last 3
        """
        if not value:
            return ""

        if pattern_type == "aws":
            return value[:4] + "*" * min(len(value) - 8, 8) + value[-4:] if len(value) > 8 else value
        if pattern_type == "jwt":
            parts = value.split(".")
            return f"{parts[0]}.***.***" if len(parts) >= 2 else value[:10] + "****"
        # generic: first 3, ****, last 3
        return value[:3] + "****" + value[-3:] if len(value) > 6 else value

    def save_endpoint(
        self,
        url: str,
        host: str,
        status_code: int | None = None,
        content_length: int | None = None,
        content_type: str | None = None,
        scan_run_id: int | None = None,
    ) -> bool:
        """Insert or update an endpoint. Returns True if new, False if already known."""
        now = datetime.now(timezone.utc).isoformat()
        existing = self.conn.execute("SELECT id FROM endpoints WHERE url = ?", (url,)).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE endpoints SET last_seen = ?, status_code = ?, "
                "content_length = ?, content_type = ?, scan_run_id = ? WHERE id = ?",
                (now, status_code, content_length, content_type, scan_run_id, existing["id"]),
            )
            self.conn.commit()
            return False
        self.conn.execute(
            "INSERT INTO endpoints (url, host, status_code, content_length, "
            "content_type, scan_run_id, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (url, host, status_code, content_length, content_type, scan_run_id, now, now),
        )
        self.conn.commit()
        return True

    def get_endpoints(self, limit: int = 500) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM endpoints ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_endpoints_by_host(self, host: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM endpoints WHERE host = ? ORDER BY url", (host,)).fetchall()
        return [dict(r) for r in rows]

    def save_secret(
        self,
        host: str,
        url: str,
        pattern_type: str,
        raw_value: str,
        store_raw: bool = False,
        scan_run_id: int | None = None,
    ) -> bool:
        """Insert or update a secret finding.  Returns True if new, False if already known.

        By default only the *redacted* version is persisted.  Pass
        ``store_raw=True`` (controlled by ``--show-full-secrets`` CLI flag)
        to also store the plaintext value in ``raw_value``.
        """
        redacted = self.redact_secret(raw_value, pattern_type)
        finding_key = hashlib.sha256(f"{host}::{pattern_type}::{url}".encode()).hexdigest()
        now = datetime.now(timezone.utc).isoformat()

        existing = self.conn.execute("SELECT id FROM secrets WHERE finding_key = ?", (finding_key,)).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE secrets SET last_seen = ?, redacted = ?, "
                "raw_value = CASE WHEN ? THEN ? ELSE raw_value END, "
                "scan_run_id = ? WHERE id = ?",
                (now, redacted, store_raw, raw_value if store_raw else None, scan_run_id, existing["id"]),
            )
            self.conn.commit()
            return False

        self.conn.execute(
            "INSERT INTO secrets (host, url, pattern_type, redacted, raw_value, "
            "scan_run_id, finding_key, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (host, url, pattern_type, redacted, raw_value if store_raw else None, scan_run_id, finding_key, now, now),
        )
        self.conn.commit()
        return True

    def get_secrets(self, limit: int = 500) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM secrets ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_secrets_by_host(self, host: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM secrets WHERE host = ? ORDER BY pattern_type", (host,)).fetchall()
        return [dict(r) for r in rows]

    def get_new_endpoints_since(self, timestamp: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM endpoints WHERE first_seen > ? ORDER BY first_seen DESC",
            (timestamp,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_new_secrets_since(self, timestamp: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM secrets WHERE first_seen > ? ORDER BY first_seen DESC",
            (timestamp,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_last_scan_timestamp(self) -> str | None:
        row = self.conn.execute("SELECT timestamp FROM scan_runs ORDER BY timestamp DESC LIMIT 1").fetchone()
        return row["timestamp"] if row else None

    def close(self) -> None:
        self.conn.close()
