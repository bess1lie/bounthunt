from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import yaml


class Scope:
    """Represents a scope configuration loaded from a YAML file.

    Validates targets against an allowlist and optional denylist before
    any active scanning takes place.

    Matching rules:
    - ``example.com`` matches ``example.com`` and all subdomains.
    - ``*.example.com`` matches subdomains only, NOT ``example.com`` itself.
    """

    def __init__(self, allowlist: Optional[List[str]] = None, denylist: Optional[List[str]] = None):
        self._allow_raw = [d.strip().lower() for d in (allowlist or [])]
        self._deny_raw = [d.strip().lower() for d in (denylist or [])]
        self._allow = [(d, d.startswith("*.")) for d in self._allow_raw]
        self._deny = [(d, d.startswith("*.")) for d in self._deny_raw]

    @property
    def allowlist(self) -> List[str]:
        """Original allow patterns as strings."""
        return list(self._allow_raw)

    @property
    def targets(self) -> List[str]:
        """Bare domains to use as scan targets (strips ``*.`` prefix)."""
        return [self._bare(d) for d in self._allow_raw if self._bare(d)]

    @staticmethod
    def _bare(pattern: str) -> str:
        return pattern[2:] if pattern.startswith("*.") else pattern

    def _matches_any(self, domain: str, patterns: list[tuple[str, bool]]) -> bool:
        domain = domain.strip().lower()
        for pat, wild in patterns:
            bare = self._bare(pat)
            if wild:
                if domain.endswith(f".{bare}"):
                    return True
            else:
                if domain == bare or domain.endswith(f".{bare}"):
                    return True
        return False

    def is_in_scope(self, domain: str) -> bool:
        """Check whether *discovered host* ``domain`` is OK to store/process.

        This is the **final decision** — should we keep this host in the
        database, report it, alert on it?  If the answer is no, the host
        is dropped.

        Example with scope ``allow=["*.example.com"]``::

            is_in_scope("sub.example.com")   # True  — subdomain of wildcard
            is_in_scope("example.com")       # False — wildcard does NOT
                                             #         include the root
            is_in_scope("evil.com")          # False — not in allowlist
        """
        if not self._allow:
            return False
        if self._matches_any(domain, self._deny):
            return False
        return self._matches_any(domain, self._allow)

    def can_scan(self, target: str) -> bool:
        """Check whether *launching recon* from ``target`` is permitted.

        This is the **go/no-go gate** — should we even start scanning?
        A wildcard ``*.example.com`` does NOT include the bare root in
        ``is_in_scope``, but we MUST be able to scan ``example.com``
        itself so that subfinder discovers ``sub.example.com``.

        Example with scope ``allow=["*.example.com"]``::

            can_scan("example.com")          # True  — wildcard root is
                                             #         a valid scan target
            can_scan("evil.com")             # False — not in allowlist

            # Contrast with is_in_scope:
            #   is_in_scope("example.com")   # False
            #   can_scan("example.com")      # True

        Example with scope ``allow=["*.example.com"], deny=["example.com"]``::

            can_scan("example.com")          # False — explicitly denied
        """
        target = target.strip().lower()
        if not self._allow:
            return False
        if self._matches_any(target, self._deny):
            return False
        if self._matches_any(target, self._allow):
            return True
        # Wildcard pattern *.X means "scan X to discover subdomains".
        for pat, wild in self._allow:
            bare = self._bare(pat)
            if wild and target == bare:
                return True
        return False

    @classmethod
    def from_file(cls, path: Path) -> Scope:
        if not path.exists():
            raise FileNotFoundError(f"Scope file not found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data:
            raise ValueError("Empty scope file")
        return cls(
            allowlist=data.get("allow", []),
            denylist=data.get("deny", []),
        )

    @classmethod
    def create_template(cls, path: Path) -> None:
        template = {
            "allow": [
                "*.example.com",
                "api.example.org",
            ],
            "deny": [
                "admin.example.com",
            ],
        }
        with open(path, "w") as f:
            yaml.dump(template, f, default_flow_style=False)
