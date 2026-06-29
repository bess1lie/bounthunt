import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from bountyhunt.core.db import Database
from bountyhunt.modules.secrets import SecretsPipeline


def _completed_process(stdout: str, returncode: int = 0):
    return MagicMock(stdout=stdout, stderr="", returncode=returncode)


def test_redact_secret_aws():
    assert Database.redact_secret("AKIA12345678ABCDEF", "aws") == "AKIA********CDEF"


def test_redact_secret_jwt():
    val = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozwNq1"
    assert Database.redact_secret(val, "jwt") == "eyJhbGciOiJIUzI1NiJ9.***.***"


def test_redact_secret_generic():
    assert Database.redact_secret("my_token_abc123xyz789012", "generic") == "my_****012"


def test_redact_secret_short():
    assert Database.redact_secret("abc", "generic") == "abc"


def test_redact_secret_empty():
    assert Database.redact_secret("", "generic") == ""


def test_secret_patterns_aws():
    body = "AKIA1234567890123456"
    pipeline = SecretsPipeline(Database(Path(tempfile.NamedTemporaryFile(suffix=".db", delete=False).name)))
    results = pipeline._scan_body(body)
    assert "aws" in results
    assert "AKIA1234567890123456" in results["aws"]


def test_secret_patterns_jwt():
    # Full JWT with 43-char signature (realistic length)
    body = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    pipeline = SecretsPipeline(Database(Path(tempfile.NamedTemporaryFile(suffix=".db", delete=False).name)))
    results = pipeline._scan_body(body)
    assert "jwt" in results


def test_secret_patterns_generic():
    body = 'api_key = "my_secret_key_abcdefgh1234567890abcd"'
    pipeline = SecretsPipeline(Database(Path(tempfile.NamedTemporaryFile(suffix=".db", delete=False).name)))
    results = pipeline._scan_body(body)
    assert "generic_token" in results


def test_secret_dedup():
    """Same host + pattern + url stored only once."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("secrets", "example.com")

        # First save
        is_new1 = db.save_secret(
            host="sub.example.com",
            url="https://sub.example.com/app.js",
            pattern_type="aws",
            raw_value="AKIA1234567890123456",
            scan_run_id=scan_id,
        )
        assert is_new1 is True

        # Second save (same key)
        is_new2 = db.save_secret(
            host="sub.example.com",
            url="https://sub.example.com/app.js",
            pattern_type="aws",
            raw_value="AKIA1234567890123456",
            scan_run_id=scan_id,
        )
        assert is_new2 is False

        assert len(db.get_secrets()) == 1

        db.close()
    finally:
        Path(tmp).unlink()


def test_secret_store_raw_false_by_default():
    """raw_value is None when store_raw=False."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("secrets", "example.com")

        db.save_secret(
            host="sub.example.com",
            url="https://sub.example.com/app.js",
            pattern_type="aws",
            raw_value="AKIA1234567890123456",
            store_raw=False,
            scan_run_id=scan_id,
        )

        secrets = db.get_secrets()
        assert secrets[0]["raw_value"] is None  # Only redacted stored

        db.close()
    finally:
        Path(tmp).unlink()


def test_secret_store_raw_true():
    """raw_value is stored when store_raw=True."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp = f.name
    try:
        db = Database(Path(tmp))
        scan_id = db.save_scan_run("secrets", "example.com")

        db.save_secret(
            host="sub.example.com",
            url="https://sub.example.com/app.js",
            pattern_type="aws",
            raw_value="AKIA1234567890123456",
            store_raw=True,
            scan_run_id=scan_id,
        )

        secrets = db.get_secrets()
        assert secrets[0]["raw_value"] == "AKIA1234567890123456"
        assert secrets[0]["redacted"] != "AKIA1234567890123456"  # Redacted is different

        db.close()
    finally:
        Path(tmp).unlink()


def test_secret_private_key_pattern():
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    pipeline = SecretsPipeline(Database(Path(tempfile.NamedTemporaryFile(suffix=".db", delete=False).name)))
    results = pipeline._scan_body(body)
    assert "private_key" in results
