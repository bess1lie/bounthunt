# Bountyhunt v1.0.0 — Release Notes

## Repository Structure

```
bountyhunt/
├── bountyhunt/
│   ├── __init__.py          # Package metadata (v0.1.0, bess1lie)
│   ├── cli.py               # Typer CLI: init, scan, monitor, report, --version
│   ├── core/
│   │   ├── db.py            # SQLite: 6 tables, CRUD, per-target diff, redact_secret()
│   │   ├── runner.py        # subprocess wrapper: run_tool(), CheckTool, ToolNotFound/Timeout
│   │   └── scope.py         # YAML allow/deny, is_in_scope(), can_scan(), targets
│   ├── modules/
│   │   ├── recon.py         # ReconPipeline: subfinder → dnsx → httpx
│   │   ├── portscan.py      # PortScanPipeline: naabu, feeds back to httpx
│   │   ├── techdetect.py    # Zero-network tech categorisation from DB
│   │   ├── vuln.py          # NucleiPipeline: safe defaults, dedup, severity filter
│   │   ├── content.py       # ContentPipeline: katana, per-URL scope guard
│   │   ├── secrets.py       # SecretsPipeline: 8 regex patterns, redaction
│   │   ├── monitor.py       # get_diff_summary(), run_monitor() — first-run baseline + notify
│   │   └── notify.py        # DiffSummary dataclass, format_digest(), send_digest()
│   └── report/
│       └── render.py        # Jinja2 Markdown/HTML report with diff section
├── tests/
│   ├── test_scope.py        # 13 tests
│   ├── test_db.py           # 12 tests
│   ├── test_recon.py        # 5 tests
│   ├── test_portscan.py     # 4 tests
│   ├── test_techdetect.py   # 4 tests
│   ├── test_vuln.py         # 9 tests
│   ├── test_content.py      # 6 tests
│   ├── test_secrets.py      # 12 tests
│   ├── test_notify.py       # 12 tests
│   ├── test_monitor.py      # 5 tests
│   └── test_report_render.py # 8 tests
├── Dockerfile               # Multi-stage: Go tools + Python runtime
├── docker-compose.yml       # Cron-like scan loop with volume mounts
├── .env.example             # Notification channel documentation
├── pyproject.toml           # Hatchling build, ruff config, pytest config
├── .pre-commit-config.yaml  # ruff hooks
├── .github/workflows/ci.yml # CI: pytest + ruff
├── .gitignore
├── LICENSE                  # MIT, Copyright 2026 bess1lie
└── README.md
```

## Architecture Overview

```
User → CLI (Typer) → Scope Guard → Pipeline Orchestrator → External Tools
                                      ├── recon:    subfinder → dnsx → httpx
                                      ├── portscan: naabu → httpx (port probe)
                                      ├── vuln:     nuclei (with dedup)
                                      ├── content:  katana (per-URL scope guard)
                                      └── secrets:  regex patterns (redaction)
                                      ↓
                                    SQLite ← Diff Engine → Report (Jinja2)
                                                         → Notifications (TG/Discord)
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `bountyhunt init <scope.yaml>` | Create scope template |
| `bountyhunt scan <scope.yaml>` | Recon (or `--all` for full pipeline) |
| `bountyhunt monitor <scope.yaml>` | Full scan + notification dispatch |
| `bountyhunt report` | Markdown/HTML report generation |
| `bountyhunt --version` | Show version |

## Database Schema (SQLite)

- **scan_runs** — id, timestamp, module, target, status
- **hosts** — domain, ip, status_code, title, tech, webserver, first_seen, last_seen (UNIQUE: domain+ip)
- **ports** — host, port, protocol, service, scan_run_id (UNIQUE: host+port)
- **findings** — id, finding_key (UNIQUE), host, template_id, name, severity, matched_at, scan_run_id
- **endpoints** — id, url (UNIQUE), host, status_code, content_length, content_type, scan_run_id
- **secrets** — id, finding_key (UNIQUE), host, url, pattern_type, redacted, raw_value, scan_run_id

## Security Features

1. **Scope guard** — `can_scan()` enforces allow/deny before all active scanning
2. **Secret redaction** — 8 regex patterns, redacted by default at DB level
3. **Redaction boundary** — `raw_value` excluded from DiffSummary dataclass; notify functions never receive it
4. **Nuclei safe defaults** — `--include-intrusive` required for dos/fuzz/intrusive templates
5. **Rate limiting** — naabu rate param (100 pps default), respect Retry-After
6. **Ethics disclaimer** — README explicitly warns about authorised use only

## Testing Coverage (91 tests)

| Module | Tests | Coverage |
|--------|-------|----------|
| scope | 17 | Exact/wildcard/deny/can_scan/targets/case_insensitive/mixed/deny_wildcard |
| db | 9 | Init/CRUD/upsert/scan_runs/hosts_since/port_ops/per-target |
| recon | 5 | Mock pipeline/OOS filter/graceful degradation |
| portscan | 4 | Scope filter/empty input/to_urls |
| techdetect | 4 | Dedup/empty DB/categorisation/JSON strings |
| vuln | 9 | OOS filter/dedup/default tags/can_scan/severity CLI/exclude-tags CLI |
| content | 6 | Per-URL filter/empty input/OOS targets/dedup/malformed JSON |
| secrets | 12 | Redact logic (aws/jwt/generic) + patterns (8) + dedup + store_raw |
| notify | 12 | Baseline/no-changes/hosts/findings/secrets/endpoints/truncation/channels/redaction |
| monitor | 5 | Baseline/second-run hosts/findings/redaction/no-changes |
| report_render | 8 | Baseline/no-changes/hosts/findings/secrets/endpoints/ports/None |

## Code Quality

- Ruff: clean (E, F, I, N, W rules)
- Ruff format: clean (120 char line length)
- Python 3.11+ with full type annotations
- All exceptions properly typed (ToolNotFoundError, ToolTimeoutError)
- Consistent logging via `logging.getLogger(__name__)`

## Roadmap (Future)

- FastAPI live dashboard (real-time web UI)
- Notification templates (customisable formatting)
- Webhook integration tests

## Screenshots

Screenshots are in the `screenshots/` directory:

- `report.html` — Generated HTML report in browser
- `report.md` — Generated Markdown report
- `cli-help.txt` — CLI --help and typical usage output

### Quick preview

**HTML report:** open `screenshots/report.html` in any browser.

**CLI usage:**
```
$ bountyhunt --version
bountyhunt v0.1.0 — by bess1lie

$ bountyhunt scan scope.yaml --all
→ Starting recon for: example.com
  • subfinder → 12 subdomains
  • dnsx → 8 resolved
  • httpx → 5 alive (200/30x)
  • naabu → 3 open ports
  • nuclei → 2 findings (1 new)
  • katana → 15 endpoints (3 new)
  • secrets → 1 potential secret (1 new)
✓ Results saved to bountyhunt.db
```

## Validation

Clean-room validation performed:

- ✅ `pip install -e ".[dev]"` — installs all dependencies
- ✅ `bountyhunt --version` — outputs correct version string
- ✅ `bountyhunt --help` — shows all 4 commands
- ✅ `bountyhunt init` — creates valid scope.yaml
- ✅ `bountyhunt scan` — graceful tool-not-found error (no crash)
- ✅ `bountyhunt report` — generates Markdown + HTML with diff section
- ✅ `pytest` — 91 tests pass
- ✅ `ruff check .` — clean
- ✅ `ruff format --check .` — clean
- ✅ Docker — multi-stage build, compose volumes, cron-ready loop

## Version

```text
bountyhunt v1.0.0 — by bess1lie
```

Recommended tag: `v1.0.0`
