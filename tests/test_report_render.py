from bountyhunt.modules.notify import DiffSummary
from bountyhunt.report.render import _render_diff_templates


def test_render_diff_baseline():
    """Baseline diff shows info message."""
    diff = DiffSummary(target="example.com", scan_timestamp="now", is_baseline=True)
    html = _render_diff_templates(diff)
    assert "Baseline run" in html


def test_render_diff_no_changes():
    """Empty diff shows no-changes message."""
    diff = DiffSummary(target="example.com", scan_timestamp="now")
    html = _render_diff_templates(diff)
    assert "No new findings since last scan" in html


def test_render_diff_hosts():
    diff = DiffSummary(
        target="example.com",
        scan_timestamp="now",
        hosts=[{"domain": "sub.example.com", "ip": "1.2.3.4", "status_code": 200, "title": "Test"}],
    )
    html = _render_diff_templates(diff)
    assert "New Hosts" in html
    assert "sub.example.com" in html


def test_render_diff_findings():
    diff = DiffSummary(
        target="example.com",
        scan_timestamp="now",
        findings=[{"host": "sub.example.com", "template_id": "test", "name": "XSS", "severity": "HIGH"}],
    )
    html = _render_diff_templates(diff)
    assert "New Findings" in html
    assert "XSS" in html


def test_render_diff_secrets_redacted():
    """Secrets in diff are redacted — no raw_value."""
    diff = DiffSummary(
        target="example.com",
        scan_timestamp="now",
        secrets=[
            {
                "host": "sub.example.com",
                "url": "https://sub.example.com/app.js",
                "pattern_type": "aws",
                "redacted": "AKIA****ABCD",
            }
        ],
    )
    html = _render_diff_templates(diff)
    assert "New Secrets" in html
    assert "AKIA****ABCD" in html
    assert "raw_value" not in html


def test_render_diff_endpoints():
    diff = DiffSummary(
        target="example.com",
        scan_timestamp="now",
        endpoints=[{"url": "https://sub.example.com/page", "status_code": 200}],
    )
    html = _render_diff_templates(diff)
    assert "New Endpoints" in html


def test_render_diff_ports():
    diff = DiffSummary(
        target="example.com",
        scan_timestamp="now",
        ports=[{"host": "1.2.3.4", "port": 8080, "protocol": "tcp"}],
    )
    html = _render_diff_templates(diff)
    assert "New Ports" in html
    assert "8080" in html


def test_diff_is_none():
    """None diff produces empty string."""
    assert _render_diff_templates(None) == ""
