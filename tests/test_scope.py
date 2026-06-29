import tempfile
from pathlib import Path

import yaml

from bountyhunt.core.scope import Scope


def test_is_in_scope_exact_match():
    scope = Scope(allowlist=["example.com"])
    assert scope.is_in_scope("example.com")
    assert not scope.is_in_scope("evil.com")


def test_is_in_scope_wildcard():
    scope = Scope(allowlist=["*.example.com"])
    assert scope.is_in_scope("sub.example.com")
    assert not scope.is_in_scope("example.com")
    assert not scope.is_in_scope("evil.com")


def test_is_in_scope_denylist():
    scope = Scope(allowlist=["*.example.com"], denylist=["admin.example.com"])
    assert scope.is_in_scope("sub.example.com")
    assert not scope.is_in_scope("admin.example.com")


def test_is_in_scope_empty_allowlist():
    scope = Scope()
    assert not scope.is_in_scope("anything.com")


def test_from_file():
    data = {"allow": ["*.example.com"], "deny": ["admin.example.com"]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        tmp = f.name
    try:
        scope = Scope.from_file(Path(tmp))
        assert scope.is_in_scope("api.example.com")
        assert not scope.is_in_scope("admin.example.com")
    finally:
        Path(tmp).unlink()


def test_create_template():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        tmp = f.name
    try:
        Scope.create_template(Path(tmp))
        content = Path(tmp).read_text()
        assert "*.example.com" in content
        assert "allow" in content
    finally:
        Path(tmp).unlink()


def test_case_insensitive():
    scope = Scope(allowlist=["Example.COM"])
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("EXAMPLE.COM")


def test_subdomain_of_wildcard():
    scope = Scope(allowlist=["*.example.com"])
    assert scope.is_in_scope("deep.sub.example.com")


def test_multiple_allow_patterns():
    scope = Scope(allowlist=["example.com", "*.test.org"])
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("sub.test.org")
    assert not scope.is_in_scope("other.com")


def test_deny_exact_overrides_allow_wildcard():
    scope = Scope(allowlist=["*.target.com"], denylist=["staging.target.com"])
    assert scope.is_in_scope("sub.target.com")
    assert scope.is_in_scope("dev.target.com")
    assert not scope.is_in_scope("staging.target.com")


def test_deny_wildcard_overrides_allow_wildcard():
    scope = Scope(allowlist=["*.target.com"], denylist=["*.internal.target.com"])
    assert scope.is_in_scope("www.target.com")
    assert not scope.is_in_scope("sub.internal.target.com")
    assert not scope.is_in_scope("deep.sub.internal.target.com")
    assert scope.is_in_scope("internal.target.com")


def test_allow_subdomains_of_exact_match():
    scope = Scope(allowlist=["target.com"])
    assert scope.is_in_scope("target.com")
    assert scope.is_in_scope("www.target.com")
    assert scope.is_in_scope("deep.sub.target.com")
    assert not scope.is_in_scope("not-target.com")
    assert not scope.is_in_scope("evil.com")


def test_can_scan_allows_root_of_wildcard():
    scope = Scope(allowlist=["*.example.com"])
    assert scope.can_scan("example.com")
    assert not scope.can_scan("evil.com")


def test_can_scan_blocks_denied_target():
    scope = Scope(allowlist=["*.example.com"], denylist=["example.com"])
    assert not scope.can_scan("example.com")


def test_can_scan_exact_allow():
    scope = Scope(allowlist=["api.example.org"])
    assert scope.can_scan("api.example.org")
    assert not scope.can_scan("example.org")


def test_targets_property():
    scope = Scope(allowlist=["*.example.com", "api.example.org"])
    assert scope.targets == ["example.com", "api.example.org"]


def test_mixed_multiple_allow_deny():
    scope = Scope(
        allowlist=["*.example.com", "api.example.org", "example.net"],
        denylist=["admin.example.com", "*.internal.example.com", "old.example.net"],
    )
    assert scope.is_in_scope("app.example.com")
    assert scope.is_in_scope("api.example.org")
    assert scope.is_in_scope("example.net")
    assert scope.is_in_scope("sub.example.net")
    assert not scope.is_in_scope("admin.example.com")
    assert not scope.is_in_scope("sub.internal.example.com")
    assert not scope.is_in_scope("old.example.net")
    assert not scope.is_in_scope("evil.org")
