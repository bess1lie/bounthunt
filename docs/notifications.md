# Notifications

Bountyhunt sends diff digests to Discord and/or Telegram when new findings
appear between scan runs. Notifications are **only** triggered by the
`monitor` command — `scan` and `report` never send anything.

## Configuration via environment variables

Bountyhunt reads credentials from the environment. Copy `.env.example` to
`.env` and fill in the channels you want:

```bash
cp .env.example .env
$EDITOR .env
```

`.env.example` contents:

```
# Discord webhook URL (optional — omit to disable Discord notifications)
# DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your-webhook-id/your-webhook-token

# Telegram bot token and chat ID (optional — omit to disable Telegram notifications)
# TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234...
# TELEGRAM_CHAT_ID=-1001234567890
```

| Variable | Required for | Example |
|---|---|---|
| `DISCORD_WEBHOOK_URL` | Discord | `https://discord.com/api/webhooks/<id>/<token>` |
| `TELEGRAM_BOT_TOKEN` | Telegram | `123456:ABC-DEF1234...` |
| `TELEGRAM_CHAT_ID` | Telegram | `-1001234567890` |

- Discord is enabled if `DISCORD_WEBHOOK_URL` is set.
- Telegram is enabled if **both** `TELEGRAM_BOT_TOKEN` and
  `TELEGRAM_CHAT_ID` are set.
- If neither is configured, bountyhunt logs "No notification channels
  configured" and continues silently.

## Trigger: `monitor` only

```bash
bountyhunt monitor scope.yaml
```

The `monitor` command is designed for cron or systemd. It:

1. Runs the recon pipeline for each target in scope.
2. Compares the result against the last scan run for that target.
3. **First run for a target** establishes a silent baseline — no notification
   is sent. Subsequent runs produce a diff.
4. If the diff is non-empty, renders a Markdown digest and sends it to every
   configured channel.
5. Prints a per-target summary: `Baseline established`, `Notifications sent:
   <channels>`, `Notification failures: <channels>`, or `No new findings`.

`scan` and `report` do **not** send notifications, even if env vars are set.

## Digest format

The digest is plain Markdown text with sections, each capped at 10 items:

```
bountyhunt digest — example.com — 2026-06-30 12:00 UTC

*🌐 Hosts — 3 new*
  - sub.example.com (200, nginx)
  - api.example.com (200, FastAPI)
  - …and 1 more

*🔌 Ports — 2 new*
  - sub.example.com:8443
  - api.example.com:9090

*📁 Endpoints — 5 new*

*⚠️ Potential Findings — 2 new*
  - CVE-XXXX-XXXX on sub.example.com (high)

*🔑 Secrets — 1 new (redacted)*
  - AKIA************ABCD on api.example.com (aws)

⚠️ Manual verification required before reporting findings.
```

## Secret redaction

The digest never includes raw secret values. The `DiffSummary` dataclass that
feeds the notification sender only has a `redacted` field — `raw_value` is
stripped before the summary is built, regardless of whether `--show-full-secrets`
was used during the scan. Redaction rules:

| Pattern type | Redaction format | Example |
|---|---|---|
| `aws` | first 4 + `****` + last 4 | `AKIA************ABCD` |
| `jwt` | header + `.***.***` | `eyJhbGci.***.***` |
| `generic` | first 3 + `****` + last 3 | `api_****xyz` |

## Sending a test message

There is no dedicated test command. To verify your webhook works, run a
`monitor` cycle twice against a target that produces a finding:

```bash
# first run — baseline, silent
bountyhunt monitor scope.yaml
# introduce a change, then run again — should send
bountyhunt monitor scope.yaml
```

## Docker

When running with Docker, mount a `.env` file or pass env vars to the service.
See [docker.md](docker.md).

## Delivery semantics

- Discord: POST `{"content": text}` to the webhook URL, 15 s timeout. The
  text is truncated to 2000 characters (Discord's limit).
- Telegram: POST to `https://api.telegram.org/bot{token}/sendMessage` with
  `chat_id`, `text` (truncated to 4096), `parse_mode=Markdown`,
  `disable_web_page_preview=true`, 15 s timeout.
- Each channel returns a boolean. The monitor command prints
  `Notifications sent: ['discord', 'telegram']` and
  `Notification failures: []` (or vice versa) so you can see which channel
  failed without aborting the run.
