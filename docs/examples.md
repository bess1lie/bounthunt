# Examples

End-to-end workflows for bountyhunt v1.1.0. All commands assume you are in the
repo root and have `scope.yaml` ready (see [scope.md](scope.md)).

## 1. First-time workflow

```bash
# create a scope file
bountyhunt init scope.yaml
# edit it with your program's domains
$EDITOR scope.yaml

# recon-only scan (subfinder -> dnsx -> httpx)
bountyhunt scan scope.yaml

# full pipeline (recon + ports + content + secrets + nuclei + techdetect)
bountyhunt scan scope.yaml --all

# generate an HTML report
bountyhunt report --format html -o report.html

# open it
xdg-open report.html
```

## 2. Single-target scan

```bash
# scan one domain without editing scope.yaml (scope still enforced)
bountyhunt scan scope.yaml --target example.com --all
```

`can_scan("example.com")` is still checked against `scope.yaml`. If the
target is out of scope, the command is refused.

## 3. Monitor loop with notifications

Set up env vars first (see [notifications.md](notifications.md)):

```bash
export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
export TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
export TELEGRAM_CHAT_ID=-1001234567890
```

Then run on a schedule. With cron:

```cron
# every 6 hours
0 */6 * * * cd /path/to/bounthunt && bountyhunt monitor scope.yaml >> /var/log/bountyhunt.log 2>&1
```

- First run for each target: silent baseline, no notification.
- Subsequent runs: diff against the last scan, send a digest to Discord and
  Telegram if anything new appeared.

With systemd, a minimal unit:

```ini
# /etc/systemd/system/bountyhunt.service
[Service]
WorkingDirectory=/path/to/bounthunt
EnvironmentFile=/path/to/bounthunt/.env
ExecStart=/usr/local/bin/bountyhunt monitor /path/to/bounthunt/scope.yaml
```

```ini
# /etc/systemd/system/bountyhunt.timer
[Timer]
OnCalendar=*-*-* 00/6:00:00
[Install]
WantedBy=timers.target
```

## 4. Resume after interruption

Bountyhunt writes a checkpoint per `(target, module)` to the `checkpoints`
table. If a scan is killed (Ctrl+C, crash, timeout), the next run prompts:

```
Resume from last checkpoint? [Y/n]:
```

- `Y` (default) — skip modules that completed successfully.
- `n` — start fresh.
- `--no-resume` — skip the prompt and always start fresh:

```bash
bountyhunt scan scope.yaml --all --no-resume
```

## 5. Nuclei severity filter

```bash
# only high and critical
bountyhunt scan scope.yaml --all --severity high,critical

# include intrusive templates (dos/fuzz/intrusive) — use with caution
bountyhunt scan scope.yaml --all --include-intrusive
```

Default severity filter is `low,medium,high,critical`. Intrusive tags
(`dos`, `fuzz`, `intrusive`) are excluded by default.

## 6. Diff report for one target

```bash
# run two scans some time apart
bountyhunt scan scope.yaml --all
# ... time passes, target changes ...
bountyhunt scan scope.yaml --all --target example.com

# generate a report with a diff section for that target
bountyhunt report --target example.com --format html -o report.html
```

The report includes a "Changes Since Last Scan" section with new hosts, ports,
findings, endpoints and secrets. If only one scan run exists for the target,
the section reads "Baseline established — no previous scan to compare.".

## 7. Rate limiting port scans

```bash
# naabu at 50 packets/sec instead of the default 100
bountyhunt scan scope.yaml --all --rate 50
```

`--rate` controls naabu's `-rate` flag (packets per second).

## 8. Secrets handling

By default, secrets are stored redacted in the database:

```bash
bountyhunt scan scope.yaml --all
bountyhunt report --format markdown -o report.md
# report shows: AKIA************ABCD (aws) on api.example.com
```

To store and display raw values (only on trusted hosts, never on shared
machines):

```bash
bountyhunt scan scope.yaml --all --show-full-secrets
```

> **Note:** even with `--show-full-secrets`, the **notification digest**
> produced by `monitor` never includes raw values. Redaction at the
> notification layer is unconditional. See
> [notifications.md](notifications.md#secret-redaction).

## 9. Docker: scheduled full scan

```bash
docker compose up -d
docker compose logs -f
```

The default compose service runs `scan scope.yaml --all` + regenerates a
report every 6 hours. See [docker.md](docker.md).

## 10. Complete pipeline diagram

```
scope.yaml
   │
   ▼
bountyhunt scan --all
   │
   ├── recon       subfinder → dnsx → httpx
   ├── portscan    naabu → httpx re-probe of non-standard ports
   ├── content     katana (depth 2, JS crawl)
   ├── secrets     regex scan on fetched bodies
   ├── vuln        nuclei (default severity, intrusive excluded)
   └── techdetect  summary from httpx tech-detect in DB
   │
   ▼
bountyhunt.db (SQLite, 7 tables)
   │
   ▼
bountyhunt report --format html -o report.html
```

Each stage writes a checkpoint. Interruptions resume from the last completed
stage.
