# Minimal Kali-based recon sidecar — NOT privileged.
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    whois \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/bash precog
USER precog
WORKDIR /home/precog

CMD ["sleep", "infinity"]
