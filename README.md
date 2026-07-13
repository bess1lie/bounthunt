# 🎯 bounthunt — Bug Bounty Recon & Orchestration

[![PyPI version](https://img.shields.io/pypi/v/bounthunt?color=blue&style=flat-square)](https://pypi.org/project/bounthunt/)
[![Python version](https://img.shields.io/pypi/pyversions/bounthunt?style=flat-square)](https://pypi.org/project/bounthunt/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/bess1lie/bounthunt/ci.yml?branch=main&style=flat-square)](https://github.com/bess1lie/bounthunt/actions)
[![Code Coverage](https://img.shields.io/badge/coverage-95%25-green?style=flat-square)](https://github.com/bess1lie/bounthunt)
[![Style: Black](https://img.shields.io/badge/style-black-000000?style=flat-square)](https://github.com/psf/black)
[![Type: Mypy](https://img.shields.io/badge/types-mypy-blue?style=flat-square)](http://mypy-lang.org/)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow?style=flat-square)](https://github.com/PyCQA/bandit)
[![Stars](https://img.shields.io/github/stars/bess1lie/bounthunt?style=flat-square)](https://github.com/bess1lie/bounthunt/stargazers)
[![Issues](https://img.shields.io/github/issues/bess1lie/bounthunt?style=flat-square)](https://github.com/bess1lie/bounthunt/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/bess1lie/bounthunt/pulls)

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

## 🛠️ Built With

- **Language:** Python 3.11+
- **Orchestration:** subfinder · dnsx · httpx · naabu · nuclei · katana
- **Database:** SQLite
- **Reports:** Jinja2
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

## ⚡ Quick Start

### Prerequisites
- Python 3.11+
- Docker (recommended) or Go tools installed locally

### Using Docker (Recommended)
```bash
docker compose build
docker compose run --rm bounthunt scan /data/scope.yaml --all
docker compose up -d
```

### Using Source
```bash
git clone https://github.com/bess1lie/bounthunt.git
cd bounthunt
pip install .
bounthunt init scope.yaml
bounthunt scan scope.yaml --all
```

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
