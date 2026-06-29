import tempfile
from pathlib import Path
from unittest.mock import patch

from bountyhunt.core.db import Database
from bountyhunt.core.scope import Scope
from bountyhunt.modules.monitor import run_monitor

SCOPE = Scope(allowlist=["example.com", "*.example.com"])


def _mock_scan(scope, db, targets):
    """Simulate a scan that produces some results in the DB."""
    scan_id = db.save_scan_run("recon", targets[0])
    db.upsert_host("sub.example.com", ip="1.2.3.4", status_code=200, scan_run_id=scan_id)
    db.save_finding(
        host="sub.example.com",
        template_id="test-tpl",
        matched_at="sub.example.com:443",
        name="Test",
        severity="MEDIUM",
        scan_run_id=scan_id,
    )
    db.save_secret(
        host="sub.example.com",
        url="https://sub.example.com/app.js",
        pattern_type="aws",
        raw_value="AKIA1234567890123456",
        store_raw=False,
        scan_run_id=scan_id,
    )


def test_first_run_baseline():
    """No previous scan → baseline established, no notifications."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        result = run_monitor(SCOPE, db, "example.com", _mock_scan)
        assert result.get("baseline") is True
        assert result.get("discord") is None  # no channels configured

        # Second run detects these as new since baseline
        last_ts = db.get_last_scan_for_target("example.com")
        assert last_ts is not None

        hosts = db.get_hosts_for_target_since("example.com", "2000-01-01")
        assert len(hosts) == 1

        db.close()
    finally:
        Path(tmp).unlink()


def test_second_run_detects_new_hosts():
    """Second run detects new hosts added since baseline."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))

        # First run: establish baseline
        run_monitor(SCOPE, db, "example.com", _mock_scan)

        # Second run: add a new host
        def _second_scan(scope, db, targets):
            _mock_scan(scope, db, targets)
            scan_id = db.save_scan_run("recon", targets[0])
            db.upsert_host("new.example.com", ip="5.6.7.8", status_code=200, scan_run_id=scan_id)

        with patch("bountyhunt.modules.monitor.send_digest") as mock_send:
            mock_send.return_value = {"discord": True}
            run_monitor(SCOPE, db, "example.com", _second_scan)

        # send_digest was called with one new host
        call_args = mock_send.call_args[0][0]
        assert len(call_args.hosts) == 1
        assert call_args.hosts[0]["domain"] == "new.example.com"
        assert call_args.is_baseline is False

        db.close()
    finally:
        Path(tmp).unlink()


def test_second_run_detects_new_findings():
    """Second run detects new findings."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        run_monitor(SCOPE, db, "example.com", _mock_scan)

        def _second_scan(scope, db, targets):
            _mock_scan(scope, db, targets)
            scan_id = db.save_scan_run("nuclei", targets[0])
            db.save_finding(
                host="sub.example.com",
                template_id="new-tpl",
                matched_at="sub.example.com:8443",
                name="New Finding",
                severity="HIGH",
                scan_run_id=scan_id,
            )

        with patch("bountyhunt.modules.monitor.send_digest") as mock_send:
            mock_send.return_value = {"discord": True}
            run_monitor(SCOPE, db, "example.com", _second_scan)

        call_args = mock_send.call_args[0][0]
        assert len(call_args.findings) == 1
        assert call_args.findings[0]["template_id"] == "new-tpl"

        db.close()
    finally:
        Path(tmp).unlink()


def test_redaction_boundary_enforced():
    """raw_value is stripped from secrets before notify receives them."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))

        # Insert a secret with raw_value
        run_monitor(SCOPE, db, "example.com", _mock_scan)

        def _second_scan(scope, db, targets):
            _mock_scan(scope, db, targets)
            scan_id = db.save_scan_run("secrets", targets[0])
            db.save_secret(
                host="sub.example.com",
                url="https://sub.example.com/keys",
                pattern_type="aws",
                raw_value="AKIA9999999999999999",
                store_raw=True,
                scan_run_id=scan_id,
            )

        with patch("bountyhunt.modules.monitor.send_digest") as mock_send:
            mock_send.return_value = {"discord": True}
            run_monitor(SCOPE, db, "example.com", _second_scan)

        call_args = mock_send.call_args[0][0]
        assert len(call_args.secrets) == 1
        assert "raw_value" not in call_args.secrets[0]
        assert call_args.secrets[0]["redacted"] == "AKIA********9999"

        db.close()
    finally:
        Path(tmp).unlink()


def test_second_run_no_changes():
    """No new items → digest with no changes."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        run_monitor(SCOPE, db, "example.com", _mock_scan)

        with patch("bountyhunt.modules.monitor.send_digest") as mock_send:
            mock_send.return_value = {"discord": True}
            run_monitor(SCOPE, db, "example.com", _mock_scan)

        call_args = mock_send.call_args[0][0]
        assert len(call_args.hosts) == 0
        assert len(call_args.findings) == 0
        assert len(call_args.secrets) == 0
        assert call_args.is_baseline is False

        db.close()
    finally:
        Path(tmp).unlink()
