import tempfile
from pathlib import Path

from bountyhunt.core.db import Database
from bountyhunt.modules.techdetect import get_tech_by_category, get_tech_summary


def test_get_tech_summary():
    """Returns deduplicated (domain, tech_list) pairs from stored hosts."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("recon", "example.com")
        db.upsert_host("a.example.com", tech=["nginx", "PHP"], scan_run_id=scan_id)
        db.upsert_host("b.example.com", tech=["Apache"], scan_run_id=scan_id)
        db.upsert_host("a.example.com", tech=["nginx", "PHP"], scan_run_id=scan_id)  # duplicate

        summary = get_tech_summary(db)
        assert len(summary) == 2
        techs = {e["domain"]: e["tech"] for e in summary}
        assert techs["a.example.com"] == ["nginx", "PHP"]
        assert techs["b.example.com"] == ["Apache"]

        db.close()
    finally:
        Path(tmp).unlink()


def test_get_tech_summary_empty():
    """Empty DB returns empty list."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        assert get_tech_summary(db) == []
        db.close()
    finally:
        Path(tmp).unlink()


def test_get_tech_by_category():
    """Technologies are grouped correctly."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("recon", "example.com")
        db.upsert_host("a.example.com", tech=["nginx", "PHP"], scan_run_id=scan_id)
        db.upsert_host("b.example.com", tech=["nginx", "Python"], scan_run_id=scan_id)

        cats = get_tech_by_category(db)
        assert sorted(cats.keys()) == sorted(["nginx", "PHP", "Python"])
        assert set(cats["nginx"]) == {"a.example.com", "b.example.com"}
        assert cats["PHP"] == ["a.example.com"]
        assert cats["Python"] == ["b.example.com"]

        db.close()
    finally:
        Path(tmp).unlink()


def test_get_tech_from_json_string():
    """Handle tech stored as JSON string in DB."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("recon", "example.com")
        db.upsert_host("a.example.com", tech=["nginx"], scan_run_id=scan_id)

        # Verify the tech is stored as JSON string
        row = db.conn.execute("SELECT tech FROM hosts WHERE domain = ?", ("a.example.com",)).fetchone()
        assert row["tech"] == '["nginx"]'

        summary = get_tech_summary(db)
        assert summary[0]["tech"] == ["nginx"]

        db.close()
    finally:
        Path(tmp).unlink()
