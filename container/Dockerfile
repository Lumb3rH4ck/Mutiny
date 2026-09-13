FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        clamav \
        yara \
        strace \
        libarchive-tools \
        file \
        ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/mutiny-scan-entrypoint
RUN chmod +x /usr/local/bin/mutiny-scan-entrypoint

ENTRYPOINT ["/usr/local/bin/mutiny-scan-entrypoint"]