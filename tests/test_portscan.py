import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from bountyhunt.core.db import Database
from bountyhunt.core.scope import Scope
from bountyhunt.modules.portscan import PortScanPipeline


def _completed_process(stdout: str, returncode: int = 0):
    return MagicMock(stdout=stdout, stderr="", returncode=returncode)


SCOPE = Scope(allowlist=["example.com", "*.example.com"])


def test_portscan_filters_out_of_scope():
    """Ports for OOS hosts are skipped even if naabu reports them."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = PortScanPipeline(SCOPE, db)
        scan_id = db.save_scan_run("portscan", "example.com")

        resolved = [
            {"domain": "sub.example.com", "ip": "1.2.3.4"},
            {"domain": "evil.com", "ip": "9.9.9.9"},
        ]

        fake_naabu = (
            '{"host":"1.2.3.4","port":80,"protocol":"tcp"}\n'
            '{"host":"1.2.3.4","port":443,"protocol":"tcp"}\n'
            '{"host":"9.9.9.9","port":8080,"protocol":"tcp"}\n'
        )

        with patch("bountyhunt.modules.portscan.run_tool", return_value=_completed_process(fake_naabu)):
            ports = pipeline.run(resolved, scan_id)

        assert len(ports) == 2
        assert all(p["port"] in (80, 443) for p in ports)

        saved = db.get_ports_by_scan_run_id(scan_id)
        assert len(saved) == 2

        db.close()
    finally:
        Path(tmp).unlink()


def test_to_urls():
    ports = [
        {"host": "1.2.3.4", "port": 80, "protocol": "tcp"},
        {"host": "1.2.3.4", "port": 443, "protocol": "tcp"},
        {"host": "1.2.3.4", "port": 8080, "protocol": "tcp"},
        {"host": "1.2.3.4", "port": 8443, "protocol": "tcp"},
        {"host": "1.2.3.4", "port": 9000, "protocol": "tcp"},
    ]
    urls = PortScanPipeline.to_urls(ports)
    assert urls == [
        "http://1.2.3.4:80",
        "https://1.2.3.4:443",
        "http://1.2.3.4:8080",
        "https://1.2.3.4:8443",
        "http://1.2.3.4:9000",
    ]


def test_portscan_empty_resolved():
    """Empty resolved list returns empty result."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = PortScanPipeline(SCOPE, db)
        scan_id = db.save_scan_run("portscan", "example.com")

        with patch("bountyhunt.modules.portscan.run_tool") as mock:
            ports = pipeline.run([], scan_id)

        assert ports == []
        mock.assert_not_called()

        db.close()
    finally:
        Path(tmp).unlink()


def test_portscan_no_ips():
    """Resolved entries without IPs are skipped."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = PortScanPipeline(SCOPE, db)
        scan_id = db.save_scan_run("portscan", "example.com")

        resolved = [{"domain": "sub.example.com", "ip": ""}]

        with patch("bountyhunt.modules.portscan.run_tool") as mock:
            ports = pipeline.run(resolved, scan_id)

        assert ports == []
        mock.assert_not_called()

        db.close()
    finally:
        Path(tmp).unlink()
