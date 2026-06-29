import tempfile
from pathlib import Path

from bountyhunt.core.db import Database


def test_init_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        assert db.conn is not None
        db.close()
    finally:
        Path(tmp).unlink()


def test_save_and_get_hosts():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("recon", "example.com")
        db.upsert_host("example.com", "1.2.3.4", 200, "Example", ["nginx"], scan_run_id=scan_id)
        db.upsert_host("sub.example.com", "5.6.7.8", 301, "Redirect", scan_run_id=scan_id)
        hosts = db.get_hosts()
        assert len(hosts) == 2
        domains = {h["domain"] for h in hosts}
        assert domains == {"example.com", "sub.example.com"}
        db.close()
    finally:
        Path(tmp).unlink()


def test_upsert_updates_existing():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("recon", "example.com")
        db.upsert_host("example.com", "1.2.3.4", 200, "Old Title", scan_run_id=scan_id)
        db.upsert_host("example.com", "1.2.3.4", 200, "New Title", scan_run_id=scan_id)
        hosts = db.get_hosts()
        assert len(hosts) == 1
        assert hosts[0]["title"] == "New Title"
        db.close()
    finally:
        Path(tmp).unlink()


def test_scan_runs():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        db.save_scan_run("recon", "example.com")
        db.save_scan_run("portscan", "example.com")
        runs = db.get_scan_runs()
        assert len(runs) == 2
        assert runs[0]["module"] == "portscan"
        assert runs[1]["module"] == "recon"
        db.close()
    finally:
        Path(tmp).unlink()


def test_get_hosts_by_domain():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("recon", "example.com")
        db.upsert_host("api.example.com", "1.2.3.4", scan_run_id=scan_id)
        db.upsert_host("admin.example.com", "5.6.7.8", scan_run_id=scan_id)
        results = db.get_hosts_by_domain("api")
        assert len(results) == 1
        assert results[0]["domain"] == "api.example.com"
        db.close()
    finally:
        Path(tmp).unlink()


def test_get_hosts_since():
    from datetime import datetime, timezone

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("recon", "example.com")
        db.upsert_host("old.example.com", "1.2.3.4", scan_run_id=scan_id)
        past = datetime.now(timezone.utc).isoformat()
        db.upsert_host("new.example.com", "5.6.7.8", scan_run_id=scan_id)
        results = db.get_hosts_since(past)
        assert len(results) == 1
        assert results[0]["domain"] == "new.example.com"
        db.close()
    finally:
        Path(tmp).unlink()


def test_get_hosts_by_scan_run_id():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        s1 = db.save_scan_run("recon", "example.com")
        s2 = db.save_scan_run("recon", "test.org")
        db.upsert_host("a.example.com", scan_run_id=s1)
        db.upsert_host("b.example.com", scan_run_id=s1)
        db.upsert_host("x.test.org", scan_run_id=s2)
        hosts_s1 = db.get_hosts_by_scan_run_id(s1)
        hosts_s2 = db.get_hosts_by_scan_run_id(s2)
        assert len(hosts_s1) == 2
        assert len(hosts_s2) == 1
        assert hosts_s2[0]["domain"] == "x.test.org"
        db.close()
    finally:
        Path(tmp).unlink()


def test_get_scan_runs_for_target():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        db.save_scan_run("recon", "example.com")
        db.save_scan_run("portscan", "example.com")
        db.save_scan_run("recon", "other.org")
        runs = db.get_scan_runs_for_target("example.com")
        assert len(runs) == 2
        assert all(r["target"] == "example.com" for r in runs)
        db.close()
    finally:
        Path(tmp).unlink()


def test_get_hosts_for_target_since():
    from datetime import datetime, timezone

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        s1 = db.save_scan_run("recon", "example.com")
        s2 = db.save_scan_run("recon", "other.org")
        db.upsert_host("old.example.com", scan_run_id=s1)
        past = datetime.now(timezone.utc).isoformat()
        db.upsert_host("new.example.com", scan_run_id=s1)
        db.upsert_host("new.other.org", scan_run_id=s2)
        # Should only return new.example.com (same target, after timestamp)
        results = db.get_hosts_for_target_since("example.com", past)
        assert len(results) == 1
        assert results[0]["domain"] == "new.example.com"
        # Should NOT include new.other.org (different target)
        results_other = db.get_hosts_for_target_since("other.org", past)
        assert len(results_other) == 1
        assert results_other[0]["domain"] == "new.other.org"
        db.close()
    finally:
        Path(tmp).unlink()
