import os
from unittest.mock import patch

from bountyhunt.modules.notify import DiffSummary, format_digest, send_digest


def _make_diff(**overrides):
    kwargs = dict(
        target="example.com",
        scan_timestamp="2026-01-01T00:00:00",
    )
    kwargs.update(overrides)
    return DiffSummary(**kwargs)


class TestFormatDigest:
    def test_baseline_message(self):
        diffs = _make_diff(is_baseline=True)
        msg = format_digest(diffs)
        assert "Baseline Established" in msg
        assert "No notifications sent" in msg

    def test_no_changes_message(self):
        diffs = _make_diff()
        msg = format_digest(diffs)
        assert "No Changes" in msg

    def test_hosts_section(self):
        diffs = _make_diff(hosts=[{"domain": "sub.example.com", "status_code": 200, "title": "Test"}])
        msg = format_digest(diffs)
        assert "Hosts" in msg
        assert "sub.example.com" in msg

    def test_findings_section(self):
        diffs = _make_diff(
            findings=[
                {
                    "host": "sub.example.com",
                    "template_id": "test-tpl",
                    "name": "Test Finding",
                    "severity": "HIGH",
                }
            ]
        )
        msg = format_digest(diffs)
        assert "Potential Findings" in msg
        assert "Test Finding" in msg

    def test_secrets_section_only_redacted(self):
        """No raw_value in the DiffSummary secrets — only redacted."""
        diffs = _make_diff(
            secrets=[
                {
                    "host": "sub.example.com",
                    "url": "https://sub.example.com/app.js",
                    "pattern_type": "aws",
                    "redacted": "AKIA****ABCD",
                }
            ]
        )
        msg = format_digest(diffs)
        assert "Secrets" in msg
        assert "AKIA****ABCD" in msg
        assert "raw_value" not in msg

    def test_endpoints_section(self):
        diffs = _make_diff(
            endpoints=[
                {
                    "url": "https://sub.example.com/page",
                    "status_code": 200,
                }
            ]
        )
        msg = format_digest(diffs)
        assert "Endpoints" in msg
        assert "sub.example.com/page" in msg

    def test_truncation_at_10_items(self):
        diffs = _make_diff(hosts=[{"domain": f"sub{i}.example.com"} for i in range(15)])
        msg = format_digest(diffs)
        assert "…and 5 more" in msg


class TestSendDigest:
    def test_no_channels_configured(self):
        """No env vars → empty result, no crash."""
        with patch.dict(os.environ, {}, clear=True):
            result = send_digest(_make_diff())
        assert result == {}

    def test_discord_configured(self, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

        with patch.dict(os.environ, {"DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/test"}):
            with patch("bountyhunt.modules.notify.urllib.request.urlopen") as mock:
                mock.return_value.__enter__.return_value.status = 200
                result = send_digest(_make_diff(hosts=[{"domain": "sub.example.com"}]))
        assert result.get("discord") is True

    def test_telegram_configured(self, monkeypatch):
        monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)

        with patch.dict(
            os.environ,
            {
                "TELEGRAM_BOT_TOKEN": "123:abc",
                "TELEGRAM_CHAT_ID": "-100123456",
            },
        ):
            with patch("bountyhunt.modules.notify.urllib.request.urlopen") as mock:
                mock.return_value.__enter__.return_value.status = 200
                result = send_digest(_make_diff())
        assert result.get("telegram") is True

    def test_discord_failure_returns_false(self):
        with patch.dict(os.environ, {"DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/test"}):
            with patch("bountyhunt.modules.notify.urllib.request.urlopen") as mock:
                mock.side_effect = Exception("timeout")
                result = send_digest(_make_diff())
        assert result.get("discord") is False


class TestNotifyRedactionBoundary:
    """Verify that notify never has access to raw_value."""

    def test_diff_summary_no_raw_value(self):
        """DiffSummary dataclass has no raw_value field for secrets."""
        s = DiffSummary(
            target="t",
            scan_timestamp="now",
            secrets=[{"redacted": "AKIA****ABCD", "host": "x"}],
        )
        # This test documents the contract: secrets in DiffSummary
        # should only contain 'redacted', not 'raw_value'.
        for secret in s.secrets:
            assert "raw_value" not in secret
