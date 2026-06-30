# Installation

Bountyhunt v1.1.0 is a Python CLI that orchestrates external Go-based recon
tools. You need **Python 3.11+** and, unless you use Docker, the six
ProjectDiscovery binaries on your `PATH`.

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | >= 3.11 | 3.11, 3.12 and 3.13 are tested in CI |
| pip | any | to install the package |
| subfinder | latest | ProjectDiscovery, Go binary |
| dnsx | latest | ProjectDiscovery, Go binary |
| httpx | latest | ProjectDiscovery, Go binary |
| naabu | latest | ProjectDiscovery, Go binary |
| nuclei | latest | ProjectDiscovery, Go binary |
| katana | latest | ProjectDiscovery, Go binary |

> The six Go tools are **only required for local installs**. The Docker image
> bundles them already (see [docker.md](docker.md)).

## From source

```bash
git clone https://github.com/bess1lie/bounthunt.git
cd bounthunt
pip install .
bountyhunt --version
```

For development (adds `pytest` and `ruff`):

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Installing the Go recon tools

Each tool is installed with `go install`. You need Go 1.23+.

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

Make sure `$GOPATH/bin` (usually `~/go/bin`) is on your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Verify each tool is reachable:

```bash
subfinder -version
dnsx -version
httpx -version
naabu -version
nuclei -version
katana -version
```

On first run, nuclei needs its template repository. Bountyhunt's Docker image
does this for you; for a local install run it once:

```bash
nuclei -update-templates
```

## Verify the install

```bash
bountyhunt --version
# bountyhunt v1.1.0 — by bess1lie

bountyhunt --help
```

## Docker alternative

If you do not want to install Go and the six binaries locally, use the bundled
image. See [docker.md](docker.md) for details.

```bash
docker build -t bountyhunt .
docker run --rm -v $(pwd)/scope.yaml:/data/scope.yaml:ro bountyhunt --help
```

## Uninstall

```bash
pip uninstall bountyhunt
```

This removes the Python package and the `bountyhunt` console script. It does
not remove the Go binaries or the SQLite database (`bountyhunt.db`) you may
have created during scans.
