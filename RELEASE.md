# Bountyhunt v1.1.0 — Release Notes

## Repository Structure

```
bountyhunt/
├── bountyhunt/
│   ├── __init__.py          # Package metadata (v1.1.0, bess1lie)
│   ├── core/
│   │   ├── db.py            # SQLite: 7 tables (+checkpoints), CRUD, per-target diff, redact
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
├── tests/                   # 90+ tests across all modules
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

## What's New in v1.1.0

### Scan Checkpoint / Resume

Long scans can now be **interrupted and resumed**. The pipeline saves checkpoints
after each stage (recon, portscan, content, secrets, nuclei). On restart:

1. `bountyhunt` detects existing checkpoints in the DB
2. Prompts: *"Resume from last checkpoint?"*
3. Skips completed stages, picks up where it left off

Use `--no-resume` to ignore checkpoints and run the full pipeline from scratch.

```
$ bountyhunt scan scope.yaml --all
→ Running full pipeline...

# (interrupted after recon — Ctrl+C)

$ bountyhunt scan scope.yaml --all
⚡ Found checkpoint for: example.com
  Completed: recon
Resume from last checkpoint? [Y/n]: y
✓ Recon already completed, resuming from portscan.
→ naabu → httpx → nuclei → katana → secrets
```

### Implementation

- **checkpoints** table in SQLite with UNIQUE(target, module)
- `save_checkpoint()` / `get_checkpoints()` / `clear_checkpoints()` in Database
- Prompt via `rich.prompt.Confirm`
- Applied to both `scan` (standalone) and `monitor` (cron) modes

## CLI Commands

| Command | Description |
|---------|-------------|
| `bountyhunt init <scope.yaml>` | Create scope template |
| `bountyhunt scan <scope.yaml>` | Recon (or `--all` for full pipeline) |
| `bountyhunt monitor <scope.yaml>` | Full scan + notification dispatch |
| `bountyhunt report` | Markdown/HTML report generation |
| `bountyhunt --version` | Show version |

### New Flags

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--no-resume` | scan, monitor | Ignore checkpoints, start fresh |

## Database Schema (SQLite)

- **scan_runs** — id, timestamp, module, target, status
- **hosts** — domain, ip, status_code, title, tech, webserver, first_seen, last_seen (UNIQUE: domain+ip)
- **ports** — host, port, protocol, service, scan_run_id (UNIQUE: host+port)
- **findings** — id, finding_key (UNIQUE), host, template_id, name, severity, matched_at, scan_run_id
- **endpoints** — id, url (UNIQUE), host, status_code, content_length, content_type, scan_run_id
- **secrets** — id, finding_key (UNIQUE), host, url, pattern_type, redacted, raw_value, scan_run_id
- **checkpoints** — target, module, status, started_at, completed_at (UNIQUE: target+module)

## Security Features

1. **Scope guard** — `can_scan()` enforces allow/deny before all active scanning
2. **Secret redaction** — 8 regex patterns, redacted by default at DB level
3. **Redaction boundary** — `raw_value` excluded from DiffSummary dataclass; notify functions never receive it
4. **Nuclei safe defaults** — `--include-intrusive` required for dos/fuzz/intrusive templates
5. **Rate limiting** — naabu rate param (100 pps default), respect Retry-After
6. **Ethics disclaimer** — README explicitly warns about authorised use only

## Additional Improvements

- Version bumped to 1.1.0
- PyPI classifiers and keywords added to `pyproject.toml`
- `.session/`, `.opencode/`, `report.html`, `scope.yaml` added to `.gitignore`

## Version

```text
bountyhunt v1.1.0 — by bess1lie
```

Recommended tag: `v1.1.0`
