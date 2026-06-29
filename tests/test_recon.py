import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from bountyhunt.core.db import Database
from bountyhunt.core.scope import Scope
from bountyhunt.modules.recon import ReconPipeline


def _completed_process(stdout: str, returncode: int = 0):
    return MagicMock(stdout=stdout, stderr="", returncode=returncode)


SCOPE_WITH_ROOT = Scope(allowlist=["example.com", "*.example.com"])


def test_pipeline_filters_out_of_scope_at_each_step():
    """Scope filtering happens at subfinder output AND httpx output."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ReconPipeline(SCOPE_WITH_ROOT, db)

        fake_subfinder = (
            '{"host":"sub.example.com"}\n'
            '{"host":"evil.com"}\n'
            '{"host":"out-of-scope.org"}\n'
            '{"host":"deep.sub.example.com"}\n'
        )
        fake_dnsx = '{"host":"sub.example.com","a":["1.2.3.4"]}\n{"host":"deep.sub.example.com","a":["5.6.7.8"]}\n'
        fake_httpx = (
            '{"host":"sub.example.com","a":["1.2.3.4"],"status_code":200,'
            '"title":"Sub","tech":["nginx"],"content_length":1234,"webserver":"nginx/1.18"}\n'
            '{"host":"deep.sub.example.com","a":["5.6.7.8"],"status_code":200,'
            '"title":"Deep","tech":[],"content_length":5678,"webserver":"Apache"}\n'
        )

        def fake_run_tool(cmd, **kwargs):
            tool = cmd[0]
            if tool == "subfinder":
                return _completed_process(fake_subfinder)
            elif tool == "dnsx":
                return _completed_process(fake_dnsx)
            elif tool == "httpx":
                return _completed_process(fake_httpx)
            return _completed_process("")

        with patch("bountyhunt.modules.recon.run_tool", side_effect=fake_run_tool):
            hosts = pipeline.run("example.com")

        assert len(hosts) == 2
        domains = {h["domain"] for h in hosts}
        assert domains == {"sub.example.com", "deep.sub.example.com"}
        assert "evil.com" not in domains
        assert "out-of-scope.org" not in domains

        saved = db.get_hosts()
        assert len(saved) == 2
        assert {h["domain"] for h in saved} == domains

        db.close()
    finally:
        Path(tmp).unlink()


def test_pipeline_rejects_out_of_scope_target():
    """Pipeline refuses to run if initial target is not in scope."""
    scope = Scope(allowlist=["example.com", "*.example.com"])
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ReconPipeline(scope, db)

        with patch("bountyhunt.modules.recon.run_tool") as mock:
            hosts = pipeline.run("evil.com")

        assert hosts == []
        mock.assert_not_called()

        db.close()
    finally:
        Path(tmp).unlink()


def test_pipeline_filters_httpx_results_out_of_scope():
    """Domains from httpx that are out of scope should be dropped."""
    scope = Scope(
        allowlist=["example.com", "*.example.com"],
        denylist=["admin.example.com"],
    )
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ReconPipeline(scope, db)

        fake_subfinder = '{"host":"sub.example.com"}\n{"host":"admin.example.com"}\n'
        fake_dnsx = '{"host":"sub.example.com","a":["1.2.3.4"]}\n{"host":"admin.example.com","a":["5.6.7.8"]}\n'
        fake_httpx = (
            '{"host":"sub.example.com","a":["1.2.3.4"],"status_code":200,"title":"Sub"}\n'
            '{"host":"admin.example.com","a":["5.6.7.8"],"status_code":200,"title":"Admin"}\n'
        )

        def fake_run_tool(cmd, **kwargs):
            if cmd[0] == "subfinder":
                return _completed_process(fake_subfinder)
            elif cmd[0] == "dnsx":
                return _completed_process(fake_dnsx)
            elif cmd[0] == "httpx":
                return _completed_process(fake_httpx)
            return _completed_process("")

        with patch("bountyhunt.modules.recon.run_tool", side_effect=fake_run_tool):
            hosts = pipeline.run("example.com")

        assert len(hosts) == 1
        assert hosts[0]["domain"] == "sub.example.com"

        db.close()
    finally:
        Path(tmp).unlink()


def test_pipeline_handles_empty_subfinder():
    """No subdomains found = empty result, no crash."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ReconPipeline(SCOPE_WITH_ROOT, db)

        def fake_run_tool(cmd, **kwargs):
            return _completed_process("")

        with patch("bountyhunt.modules.recon.run_tool", side_effect=fake_run_tool):
            hosts = pipeline.run("example.com")

        assert hosts == []
        db.close()
    finally:
        Path(tmp).unlink()


def test_pipeline_handles_dnsx_failure():
    """If dnsx returns nothing, pipeline stops gracefully and httpx is not called."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        pipeline = ReconPipeline(SCOPE_WITH_ROOT, db)

        call_log = []

        def fake_run_tool(cmd, **kwargs):
            call_log.append(cmd[0])
            if cmd[0] == "subfinder":
                return _completed_process('{"host":"sub.example.com"}\n')
            return _completed_process("")

        with patch("bountyhunt.modules.recon.run_tool", side_effect=fake_run_tool):
            hosts = pipeline.run("example.com")

        assert hosts == []
        assert call_log == ["subfinder", "dnsx"]
        db.close()
    finally:
        Path(tmp).unlink()
