# Stage 1 — build Go-based recon tools
FROM golang:1.23 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ENV GO111MODULE=on \
    CGO_ENABLED=1

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Stage 2 — runtime image
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/subfinder /usr/local/bin/
COPY --from=builder /go/bin/dnsx /usr/local/bin/
COPY --from=builder /go/bin/httpx /usr/local/bin/
COPY --from=builder /go/bin/naabu /usr/local/bin/
COPY --from=builder /go/bin/nuclei /usr/local/bin/
COPY --from=builder /go/bin/katana /usr/local/bin/

WORKDIR /data

COPY pyproject.toml README.md LICENSE ./
COPY bountyhunt/ ./bountyhunt/

RUN pip install --no-cache-dir .

# Pre-download nuclei templates (takes ~30s, avoids first-run delay)
RUN nuclei -update-templates 2>/dev/null || true

ENTRYPOINT ["bountyhunt"]
CMD ["--help"]
