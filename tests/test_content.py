import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

from bountyhunt.core.db import Database
from bountyhunt.core.scope import Scope
from bountyhunt.modules.content import ContentPipeline


def _completed_process(stdout: str, returncode: int = 0):
    return MagicMock(stdout=stdout, stderr="", returncode=returncode)


SCOPE = Scope(allowlist=["example.com", "*.example.com"])


def _endpoint_json(url: str, host: str = "", status: int = 200, cl: int = 500, ct: str = "text/html"):
    return (
        json.dumps(
            {
                "url": url,
                "host": host or urlparse(url).hostname,
                "status-code": status,
                "content-length": cl,
                "content-type": ct,
            }
        )
        + "\n"
    )


def test_content_filters_oos_urls():
    """URLs whose host is OOS are filtered per-url, not just at input."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ContentPipeline(SCOPE, db)
        scan_id = db.save_scan_run("content", "example.com")

        output = _endpoint_json("https://sub.example.com/page") + _endpoint_json("https://evil.com/leak")

        with patch("bountyhunt.modules.content.run_tool", return_value=_completed_process(output)):
            endpoints = pipeline.run(["sub.example.com"], scan_id)

        assert len(endpoints) == 1
        assert endpoints[0]["host"] == "sub.example.com"

        db.close()
    finally:
        Path(tmp).unlink()


def test_content_empty_targets():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ContentPipeline(SCOPE, db)
        scan_id = db.save_scan_run("content", "example.com")

        with patch("bountyhunt.modules.content.run_tool") as mock:
            endpoints = pipeline.run([], scan_id)

        assert endpoints == []
        mock.assert_not_called()

        db.close()
    finally:
        Path(tmp).unlink()


def test_content_no_in_scope_targets():
    """All-OOS targets produce empty result."""
    scope = Scope(allowlist=["example.com"])
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ContentPipeline(scope, db)
        scan_id = db.save_scan_run("content", "example.com")

        with patch("bountyhunt.modules.content.run_tool") as mock:
            endpoints = pipeline.run(["evil.com"], scan_id)

        assert endpoints == []
        mock.assert_not_called()

        db.close()
    finally:
        Path(tmp).unlink()


def test_content_dedup():
    """Same URL stored only once (UNIQUE(url))."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ContentPipeline(SCOPE, db)
        scan_id = db.save_scan_run("content", "example.com")

        url = "https://sub.example.com/page"
        output = _endpoint_json(url)

        with patch("bountyhunt.modules.content.run_tool", return_value=_completed_process(output)):
            e1 = pipeline.run(["sub.example.com"], scan_id)

        assert len(e1) == 1
        assert e1[0]["new"] is True

        with patch("bountyhunt.modules.content.run_tool", return_value=_completed_process(output)):
            e2 = pipeline.run(["sub.example.com"], scan_id)

        assert len(e2) == 1
        assert e2[0]["new"] is False

        db.close()
    finally:
        Path(tmp).unlink()


def test_content_malformed_json():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ContentPipeline(SCOPE, db)
        scan_id = db.save_scan_run("content", "example.com")

        output = "not json\n" + _endpoint_json("https://sub.example.com/ok") + "garbage\n"

        with patch("bountyhunt.modules.content.run_tool", return_value=_completed_process(output)):
            endpoints = pipeline.run(["sub.example.com"], scan_id)

        assert len(endpoints) == 1
        assert endpoints[0]["url"] == "https://sub.example.com/ok"

        db.close()
    finally:
        Path(tmp).unlink()


def test_extract_host():
    assert ContentPipeline._extract_host("https://sub.example.com:8443/path") == "sub.example.com"
    assert ContentPipeline._extract_host("http://evil.com") == "evil.com"
    assert ContentPipeline._extract_host("sub.example.com") == "sub.example.com"
    assert ContentPipeline._extract_host("sub.example.com:8080") == "sub.example.com"
