# 🎯 bounthunt — Bug Bounty Recon & Orchestration

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=plastic&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=plastic)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/github/actions/workflow/status/bess1lie/bounthunt/ci.yml?branch=main&style=plastic)](https://github.com/bess1lie/bounthunt/actions)
[![PyPI](https://img.shields.io/badge/PyPI-bounthunt-3776AB?style=plastic&logo=pypi&logoColor=white)](https://pypi.org/project/bounthunt/)
[![Stars](https://img.shields.io/github/stars/bess1lie/bounthunt?style=plastic)](https://github.com/bess1lie/bounthunt/stargazers)
[![Issues](https://img.shields.io/github/issues/bess1lie/bounthunt?style=plastic)](https://github.com/bess1lie/bounthunt/issues)
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen?style=plastic)](https://github.com/bess1lie/bounthunt/pulls)

**Scope-aware recon orchestration for bug bounty programs.**

---

## 🚀 Demo

```bash
$ bounthunt monitor scope.yaml

🔄 Starting monitoring loop...
[INFO] Checking scope.yaml...
[INFO] Scan completed. 12 new hosts discovered.
[INFO] 2 new endpoints found on example.com
[INFO] 1 new vulnerability found via nuclei
[SUCCESS] Sending notification to Telegram...

$ bounthunt report --format html

📊 Generating diff report...
✅ Report saved to reports/diff_2026_07_12.html
```

---

## ❓ Why bounthunt?

| Question | Manual approach | With bounthunt |
| :--- | :--- | :--- |
| **What changed since last week?** | `diff` two terminal buffers | `bounthunt monitor` |
| **Did I scan out of scope?** | "Hope you checked" | Scope guard blocks it |
| **Where is my scan data?** | Scattered text files | SQLite with full history |
| **Can I share findings?** | Paste terminal output | Professional HTML/MD reports |

---

## ✨ Features

- **Scope Guard** — YAML allow/deny list prevents accidental out-of-scope scanning
- **Diff Monitoring** — Tracks new hosts, ports, findings, endpoints across scan runs
- **SQLite Persistence** — Every scan stored with timestamps, queryable and auditable
- **Professional Reports** — HTML/Markdown via Jinja2 with diff sections
- **Smart Notifications** — Telegram and Discord webhook alerts on changes
- **Dockerized Workflow** — Multi-stage Docker build, `docker compose up -d` for 24/7 scans

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **CLI:** [Typer](https://typer.tiangolo.com/)
- **Terminal output:** [Rich](https://rich.readthedocs.io/)
- **HTTP client:** [HTTPX](https://www.python-httpx.org/)
- **DB & Storage:** [SQLite](https://www.sqlite.org/)
- **Templates:** [Jinja2](https://jinja.palletsprojects.com/)
- **Config:** [PyYAML](https://pyyaml.org/)
- **Orchestration:** subfinder · dnsx · httpx · naabu · nuclei · katana
- **Reports:** HTML/Markdown via Jinja2 with diff sections
- **Notifications:** Telegram / Discord webhooks
- **Deployment:** Docker

---

## 🏗️ Architecture

```mermaid
graph TD
    S[Scope YAML] --> G{Scope Guard}
    G -->|allow| SF[subfinder]
    SF --> DX[dnsx]
    DX --> HX[httpx]
    HX --> NB[naabu]
    NB --> NC[nuclei]
    NC --> KT[katana]
    KT --> SC[secrets]
    SC --> DB[(SQLite)]
    DB --> DIFF[Diff Engine]
    DIFF --> RPT[Report]
    DIFF --> NOT[Notifications]
    NOT --> TG[Telegram]
    NOT --> DC[Discord]
    G -->|deny| X[❌ Blocked]
```

---

## 📦 Installation

```bash
# From PyPI (recommended)
pip install bounthunt
bounthunt --help

# Isolated with pipx
pipx install bounthunt

# From source (latest dev)
git clone https://github.com/bess1lie/bounthunt.git
cd bounthunt
pip install -e .
```

## ⚡ Quick Start

### Prerequisites
- Python 3.11+
- Docker (recommended) or Go tools (`subfinder`, `dnsx`, `httpx`, `naabu`, `nuclei`, `katana`) for full pipeline

### Using Docker (Recommended)
```bash
docker compose build
docker compose run --rm bounthunt scan /data/scope.yaml --all
docker compose up -d
```

### Using PyPI + scope
```bash
# 1. Create scope.yaml (allowlist — every request gated)
cat > scope.yaml <<'YAML'
targets: ["https://example.com"]
allowlist: ["example.com"]
YAML

bounthunt scan scope.yaml --all
bounthunt report --format html -o report.html
```

> Scope-aware by design — out-of-scope hosts are blocked before any tool runs. See `scope.example.yaml`.

---

## 🗺️ Roadmap

| Feature | Status |
| :--- | :--- |
| Core Recon Pipeline | ✅ |
| Scope Guard & Diff Engine | ✅ |
| SQLite Persistence | ✅ |
| Docker Deployment | ✅ |
| Real-time Web Dashboard | 🚧 In Progress |
| Custom Notification Templates | 🔮 Planned |

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <a href="https://github.com/bess1lie/apihunter">🔍 apihunter</a> ·
  <a href="https://github.com/bess1lie/gqlhunter">🚀 gqlhunter</a> ·
  <a href="https://bess1lie.github.io">🌍 bess1lie.github.io</a>
</p>
