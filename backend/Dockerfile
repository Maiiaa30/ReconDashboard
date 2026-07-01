FROM node:22-bookworm-slim

# --- System + recon tooling --------------------------------------------------
# build deps for better-sqlite3 native module; nmap + whois from apt;
# subfinder/nuclei/ffuf as pinned prebuilt release binaries (ProjectDiscovery/ffuf).
ARG SUBFINDER_VERSION=2.6.6
ARG NUCLEI_VERSION=3.3.7
ARG FFUF_VERSION=2.1.0

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       python3 make g++ ca-certificates curl unzip nmap whois \
       dnsutils iputils-ping sslscan sqlmap libpcap0.8 chromium fonts-liberation \
  && rm -rf /var/lib/apt/lists/*

# Where headless Chromium lives, for the screenshot job.
ENV CHROMIUM_PATH=/usr/bin/chromium

# Recon binaries are best-effort: a moved release URL must NOT fail the image
# build. If a download fails, the app simply reports that tool as unavailable
# and degrades gracefully (passive crt.sh-only discovery, etc.).
RUN set -ux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) GOARCH=amd64 ;; arm64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac; \
    cd /tmp; \
    ( curl -fsSL -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${GOARCH}.zip" \
      && unzip -o subfinder.zip subfinder -d /usr/local/bin ) || echo "WARN: subfinder install failed"; \
    ( curl -fsSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${GOARCH}.zip" \
      && unzip -o nuclei.zip nuclei -d /usr/local/bin ) || echo "WARN: nuclei install failed"; \
    ( curl -fsSL -o ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${GOARCH}.tar.gz" \
      && tar -xzf ffuf.tar.gz -C /usr/local/bin ffuf ) || echo "WARN: ffuf install failed"; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/nuclei /usr/local/bin/ffuf 2>/dev/null || true; \
    rm -f /tmp/*.zip /tmp/*.tar.gz; \
    subfinder -version || true; nuclei -version || true; ffuf -V || true

# Extra recon binaries (best-effort, latest release): katana (crawler), naabu
# (fast port scanner), dalfox (XSS). A failed download just marks the tool
# unavailable — the app degrades gracefully.
RUN set -ux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) GOARCH=amd64 ;; arm64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac; \
    ver() { curl -fsSL "https://api.github.com/repos/$1/releases/latest" | grep -oP '"tag_name":\s*"v?\K[^"]+' | head -1; }; \
    cd /tmp; \
    KAT="$(ver projectdiscovery/katana)"; \
    ( [ -n "$KAT" ] && curl -fsSL -o katana.zip "https://github.com/projectdiscovery/katana/releases/download/v${KAT}/katana_${KAT}_linux_${GOARCH}.zip" \
      && unzip -o katana.zip katana -d /usr/local/bin ) || echo "WARN: katana install failed"; \
    NAB="$(ver projectdiscovery/naabu)"; \
    ( [ -n "$NAB" ] && curl -fsSL -o naabu.zip "https://github.com/projectdiscovery/naabu/releases/download/v${NAB}/naabu_${NAB}_linux_${GOARCH}.zip" \
      && unzip -o naabu.zip naabu -d /usr/local/bin ) || echo "WARN: naabu install failed"; \
    DAL="$(ver hahwul/dalfox)"; \
    case "$GOARCH" in amd64) DALARCH=x86_64 ;; arm64) DALARCH=aarch64 ;; *) DALARCH=x86_64 ;; esac; \
    ( [ -n "$DAL" ] && curl -fsSL -o dalfox.tar.gz "https://github.com/hahwul/dalfox/releases/download/v${DAL}/dalfox-v${DAL}-linux-${DALARCH}.tar.gz" \
      && tar -xzf dalfox.tar.gz -C /usr/local/bin --strip-components=0 dalfox 2>/dev/null \
      || tar -xzf dalfox.tar.gz -C /usr/local/bin --wildcards --transform='s#.*/##' '*/dalfox' 2>/dev/null ) || echo "WARN: dalfox install failed"; \
    chmod +x /usr/local/bin/katana /usr/local/bin/naabu /usr/local/bin/dalfox 2>/dev/null || true; \
    rm -f /tmp/*.zip /tmp/*.tar.gz; \
    katana -version || true; naabu -version || true; dalfox version || true

# Curated SecLists wordlists for ffuf content discovery (best-effort downloads;
# a moved URL must not fail the build). Names are friendly for the UI picker.
RUN mkdir -p /usr/share/wordlists; \
    SL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content"; \
    curl -fsSL -o /usr/share/wordlists/quick-hits.txt        "$SL/quickhits.txt"                 || true; \
    curl -fsSL -o /usr/share/wordlists/common.txt            "$SL/common.txt"                    || true; \
    curl -fsSL -o /usr/share/wordlists/raft-small-words.txt  "$SL/raft-small-words.txt"          || true; \
    curl -fsSL -o /usr/share/wordlists/directories-medium.txt "$SL/directory-list-2.3-small.txt" || true; \
    curl -fsSL -o /usr/share/wordlists/api-endpoints.txt     "$SL/api/api-seen-in-wild.txt"      || true; \
    if [ ! -s /usr/share/wordlists/common.txt ]; then \
      printf 'admin\nlogin\napi\nrobots.txt\n.git/HEAD\nbackup\ntest\n.env\nadmin.php\n' > /usr/share/wordlists/common.txt; \
    fi

WORKDIR /app

# Install dependencies first for better layer caching.
COPY package.json package-lock.json* ./
# npm ci = reproducible install from the lockfile (fails if out of sync).
RUN npm ci

COPY . .

EXPOSE 3001

CMD ["npm", "run", "dev"]
