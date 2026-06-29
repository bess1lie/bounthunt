import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from bountyhunt.core.db import Database
from bountyhunt.core.scope import Scope
from bountyhunt.modules.vuln import NucleiPipeline


def _completed_process(stdout: str, returncode: int = 0):
    return MagicMock(stdout=stdout, stderr="", returncode=returncode)


SCOPE = Scope(allowlist=["example.com", "*.example.com"])


def _make_nuclei_line(
    host="sub.example.com", template="ssl-dates", name="SSL Dates", severity="medium", matched="sub.example.com:443"
):
    import json

    return (
        json.dumps(
            {
                "host": host,
                "template-id": template,
                "matched-at": matched,
                "info": {"name": name, "severity": severity, "description": "test"},
            }
        )
        + "\n"
    )


def test_nuclei_filters_out_of_scope():
    """Findings for OOS hosts are skipped even if nuclei reports them."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = NucleiPipeline(SCOPE, db)
        scan_id = db.save_scan_run("nuclei", "example.com")

        output = _make_nuclei_line(host="sub.example.com") + _make_nuclei_line(host="evil.com")

        with patch("bountyhunt.modules.vuln.run_tool", return_value=_completed_process(output)):
            findings = pipeline.run(["sub.example.com", "evil.com"], scan_id)

        assert len(findings) == 1
        assert findings[0]["host"] == "sub.example.com"

        db.close()
    finally:
        Path(tmp).unlink()


def test_nuclei_empty_targets():
    """Empty target list returns empty result."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = NucleiPipeline(SCOPE, db)
        scan_id = db.save_scan_run("nuclei", "example.com")

        with patch("bountyhunt.modules.vuln.run_tool") as mock:
            findings = pipeline.run([], scan_id)

        assert findings == []
        mock.assert_not_called()

        db.close()
    finally:
        Path(tmp).unlink()


def test_nuclei_dedup():
    """Same host + template + matched_at produces one finding (dedup)."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = NucleiPipeline(SCOPE, db)
        scan_id = db.save_scan_run("nuclei", "example.com")

        line = _make_nuclei_line()

        with patch("bountyhunt.modules.vuln.run_tool", return_value=_completed_process(line)):
            findings1 = pipeline.run(["sub.example.com"], scan_id)

        assert len(findings1) == 1
        assert findings1[0]["new"] is True

        with patch("bountyhunt.modules.vuln.run_tool", return_value=_completed_process(line)):
            findings2 = pipeline.run(["sub.example.com"], scan_id)

        assert len(findings2) == 1
        assert findings2[0]["new"] is False

        db.close()
    finally:
        Path(tmp).unlink()


def test_nuclei_exclude_tags_default():
    """Default exclude_tags includes dos, fuzz, intrusive."""
    pipeline = NucleiPipeline(SCOPE, Database(Path(tempfile.NamedTemporaryFile(suffix=".db").name)))
    assert "dos" in pipeline.exclude_tags
    assert "fuzz" in pipeline.exclude_tags
    assert "intrusive" in pipeline.exclude_tags


def test_nuclei_uses_can_scan():
    """can_scan semantics: wildcard targets scan root domain."""
    scope = Scope(allowlist=["*.example.com"])
    assert scope.can_scan("example.com") is True
    assert scope.is_in_scope("example.com") is False

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = NucleiPipeline(scope, db)
        scan_id = db.save_scan_run("nuclei", "example.com")

        line = _make_nuclei_line(host="example.com")
        with patch("bountyhunt.modules.vuln.run_tool", return_value=_completed_process(line)):
            findings = pipeline.run(["example.com"], scan_id)

        # can_scan allows the wildcard root, so finding should be saved
        assert len(findings) == 1
        assert findings[0]["host"] == "example.com"

        db.close()
    finally:
        Path(tmp).unlink()


def test_nuclei_severity_passed_to_cli():
    """Severity filter is passed to nuclei CLI, not post-filtered."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = NucleiPipeline(SCOPE, db, severity="critical,high")
        scan_id = db.save_scan_run("nuclei", "example.com")

        line = _make_nuclei_line(severity="low")
        with patch("bountyhunt.modules.vuln.run_tool") as mock:
            mock.return_value = _completed_process(line)
            pipeline.run(["sub.example.com"], scan_id)

        # Verify -severity critical,high was passed
        args = mock.call_args[0][0]
        assert "-severity" in args
        sev_idx = args.index("-severity")
        assert args[sev_idx + 1] == "critical,high"

        db.close()
    finally:
        Path(tmp).unlink()


def test_nuclei_exclude_tags_passed_to_cli():
    """exclude-tags is passed to nuclei CLI."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = NucleiPipeline(SCOPE, db, exclude_tags=["dos", "fuzz"])
        scan_id = db.save_scan_run("nuclei", "example.com")

        with patch("bountyhunt.modules.vuln.run_tool") as mock:
            mock.return_value = _completed_process("")
            pipeline.run(["sub.example.com"], scan_id)

        args = mock.call_args[0][0]
        assert "-exclude-tags" in args
        idx = args.index("-exclude-tags")
        assert args[idx + 1] == "dos,fuzz"

        db.close()
    finally:
        Path(tmp).unlink()


def test_nuclei_no_targets_in_scope():
    """All OOS targets → skip, no nuclei call."""
    scope = Scope(allowlist=["example.com"])
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = NucleiPipeline(scope, db)
        scan_id = db.save_scan_run("nuclei", "example.com")

        with patch("bountyhunt.modules.vuln.run_tool") as mock:
            findings = pipeline.run(["evil.com", "malicious.org"], scan_id)

        assert findings == []
        mock.assert_not_called()

        db.close()
    finally:
        Path(tmp).unlink()


def test_nuclei_malformed_json():
    """Malformed JSON lines are silently skipped."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = NucleiPipeline(SCOPE, db)
        scan_id = db.save_scan_run("nuclei", "example.com")

        output = (
            "not json\n"
            '{"host":"good.example.com","template-id":"test",'
            '"matched-at":"good.example.com","info":{"name":"X","severity":"low"}}\n'
            "garbage\n"
        )

        with patch("bountyhunt.modules.vuln.run_tool", return_value=_completed_process(output)):
            findings = pipeline.run(["good.example.com"], scan_id)

        assert len(findings) == 1
        assert findings[0]["host"] == "good.example.com"

        db.close()
    finally:
        Path(tmp).unlink()
