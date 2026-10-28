FROM python:3.11-slim

LABEL org.opencontainers.image.title="TorCrawl Docker"
LABEL org.opencontainers.image.description="Tor-over-Proxy crawler with Xray + Tor"
LABEL org.opencontainers.image.source="https://github.com/MikeMeliz/TorCrawl.py"

# Install Tor and utilities (allow some repos to fail through proxy)
# The base image is python:3.11-slim (Debian 12 Bookworm)
RUN apt-get update --allow-releaseinfo-change \
        -o Acquire::Check-Valid-Until=false \
        -o Acquire::Retries=5 \
        || apt-get update --allow-releaseinfo-change \
        -o Acquire::Check-Valid-Until=false \
    ; \
    apt-get install -y --no-install-recommends \
    tor \
    wget \
    unzip \
    ca-certificates \
    netcat-openbsd \
    tcpdump \
    obfs4proxy \
    && rm -rf /var/lib/apt/lists/*

# Download Xray-core (latest stable)
ARG XRAY_VERSION=latest
RUN if [ "$XRAY_VERSION" = "latest" ]; then \
        XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"; \
    else \
        XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"; \
    fi \
    && wget -q "$XRAY_URL" -O /tmp/xray.zip \
    && unzip -q /tmp/xray.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm /tmp/xray.zip \
    && mkdir -p /usr/local/share/xray

# Download webtunnel (Tor pluggable transport)
RUN wget -q "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel/-/jobs/artifacts/main/download?job=build-linux-amd64" -O /tmp/webtunnel.zip \
    && unzip -q /tmp/webtunnel.zip -d /tmp/webtunnel/ \
    && cp /tmp/webtunnel/webtunnel-client /usr/local/bin/ 2>/dev/null \
    || wget -q "https://github.com/torproject/lyrebird/releases/download/v0.6.0/lyrebird-0.6.0-linux-amd64.tar.xz" -O /tmp/lyrebird.tar.xz \
    && tar -xf /tmp/lyrebird.tar.xz -C /tmp/ \
    && cp /tmp/lyrebird-*/webtunnel-client /usr/local/bin/ 2>/dev/null \
    || echo "webtunnel download failed, continuing"; \
    chmod +x /usr/local/bin/webtunnel-client 2>/dev/null; \
    rm -rf /tmp/webtunnel* /tmp/lyrebird* 2>/dev/null

# Install Python dependencies
RUN pip install --no-cache-dir \
    pysocks \
    "beautifulsoup4>=4.15.0" \
    lxml \
    networkx \
    pyvis \
    yara-python

WORKDIR /app

# Copy application code
COPY torcrawl.py /app/
COPY modules/ /app/modules/
COPY res/ /app/res/
COPY setup.py /app/
COPY requirements.txt /app/
COPY docker/tools/fetch_nodes.py /app/docker/fetch_nodes.py
COPY docker/capture/crawl_pcap.py /app/docker/crawl_pcap.py
COPY docker/configs/top1000.txt /app/docker/configs/top1000.txt

# Copy entrypoint
COPY docker/entrypoints/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create output directory
RUN mkdir -p /app/output

ENTRYPOINT ["/entrypoint.sh"]
