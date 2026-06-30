# Docker

Bountyhunt ships with a two-stage Dockerfile that bundles the six
ProjectDiscovery Go binaries, so the image is self-contained and needs no
external tools on the host.

## Image layout

The Dockerfile has two stages:

| Stage | Base image | Purpose |
|---|---|---|
| 1 — builder | `golang:1.23` | builds subfinder, dnsx, httpx, naabu, nuclei, katana |
| 2 — runtime | `python:3.11-slim` | copies the six binaries, installs the Python package, pre-downloads nuclei templates |

The runtime stage installs `libpcap0.8` (required by naabu) and
`ca-certificates`, copies the Go binaries into `/usr/local/bin/`, copies the
`bountyhunt/` package and installs it with `pip install .`. Nuclei templates
are pre-downloaded with `nuclei -update-templates` to avoid a 30-second delay
on first scan.

## Build

```bash
docker build -t bountyhunt .
```

## Run ad-hoc commands

The entrypoint is `bountyhunt`, so any CLI command can be passed directly:

```bash
# help
docker run --rm bountyhunt --help

# init a scope file (writes to the mounted volume)
docker run --rm -v $(pwd)/data:/data bountyhunt init /data/scope.yaml

# run a recon-only scan
docker run --rm -v $(pwd)/scope.yaml:/data/scope.yaml:ro \
  -v $(pwd)/data:/data/data bountyhunt scan /data/scope.yaml

# full pipeline + HTML report
docker run --rm -v $(pwd)/scope.yaml:/data/scope.yaml:ro \
  -v $(pwd)/.env:/data/.env:ro \
  -v $(pwd)/data:/data/data \
  bountyhunt scan /data/scope.yaml --all
docker run --rm -v $(pwd)/data:/data/data \
  bountyhunt report --db /data/data/bountyhunt.db --format html -o /data/data/report.html
```

## docker-compose

`docker-compose.yml` is included. It mounts `scope.yaml` and `.env` read-only,
persists the database and reports under `./data`, and runs an infinite loop:
every 6 hours it runs a full scan (`scan scope.yaml --all`) and regenerates
a Markdown report for `example.com`.

```bash
# start the scheduled scanner in the background
docker compose up -d

# tail logs
docker compose logs -f

# stop
docker compose down
```

### Volumes

| Host path | Container path | Mode | Purpose |
|---|---|---|---|
| `./scope.yaml` | `/data/scope.yaml` | ro | scope definition |
| `./.env` | `/data/.env` | ro | notification env vars (see [notifications.md](notifications.md)) |
| `./data` | `/data/data` | rw | SQLite DB, generated reports |

### Overriding the schedule

The 6-hour loop is defined in the `command:` key of `docker-compose.yml`. To
run a different pattern, override `command` at runtime:

```bash
# one-shot full scan, then exit
docker compose run --rm --entrypoint /bin/sh bountyhunt -c \
  "bountyhunt scan /data/scope.yaml --all && \
   bountyhunt report --db /data/data/bountyhunt.db --format html -o /data/data/report.html"
```

## Environment variables

Notifications are configured via env vars read by the `monitor` command. See
[notifications.md](notifications.md) for the full list and the `.env.example`
template. With Docker, pass a `.env` file (mounted at `/data/.env`) or set
keys on the service:

```yaml
environment:
  - DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
  - TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
  - TELEGRAM_CHAT_ID=-1001234567890
```

## Database location

The default database path inside the container is `/data/bountyhunt.db`. When
running with the compose volume, it lands in `./data/bountyhunt.db` on the
host. Pass `--db /data/data/bountyhunt.db` to report/export commands so they
read the persisted file.
