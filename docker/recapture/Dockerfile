FROM docker-pure-ss:latest

# mihomo binary copied from the metacubex/mihomo image (static Go binary).
COPY bin/mihomo /usr/local/bin/mihomo
COPY pt/lyrebird /usr/local/bin/lyrebird
RUN chmod +x /usr/local/bin/mihomo /usr/local/bin/lyrebird

# Recapture scripts (capture, validator, Tor/node tests, entrypoint).
COPY *.py /app/recapture/
COPY entrypoint.sh /app/recapture/entrypoint.sh
COPY torrc.template /app/recapture/torrc.template
RUN chmod +x /app/recapture/entrypoint.sh && mkdir -p /app/output

WORKDIR /app
ENTRYPOINT ["/app/recapture/entrypoint.sh"]
