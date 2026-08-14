FROM node:22-bookworm-slim

# --- System + recon tooling --------------------------------------------------
# build deps for better-sqlite3 native module; nmap + whois from apt;
# subfinder/nuclei/ffuf as pinned prebuilt release binaries (ProjectDiscovery/ffuf).
ARG SUBFINDER_VERSION=2.6.6
ARG DNSX_VERSION=1.3.0
ARG HTTPX_VERSION=1.10.0
ARG NUCLEI_VERSION=3.3.7
ARG FFUF_VERSION=2.1.0

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       python3 make g++ ca-certificates curl unzip nmap whois gosu \
       dnsutils iputils-ping sslscan sqlmap libpcap0.8 chromium chromium-sandbox fonts-liberation \
  && rm -rf /var/lib/apt/lists/*

# Where headless Chromium lives, for the screenshot job.
ENV CHROMIUM_PATH=/usr/bin/chromium

# The continuous-discovery pipeline depends on subfinder, dnsx, and httpx. Keep
# their versions deterministic and fail the image build if any core binary is
# missing; a deploy must never produce a superficially healthy but incomplete
# scanner image. Optional tools below still degrade gracefully.
RUN set -ux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) GOARCH=amd64 ;; arm64) GOARCH=arm64 ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac; \
    cd /tmp; \
    curl --retry 4 --retry-all-errors -fsSL -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${GOARCH}.zip"; \
    unzip -o subfinder.zip subfinder -d /usr/local/bin; \
    curl --retry 4 --retry-all-errors -fsSL -o dnsx.zip "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${GOARCH}.zip"; \
    unzip -o dnsx.zip dnsx -d /usr/local/bin; \
    curl --retry 4 --retry-all-errors -fsSL -o httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${GOARCH}.zip"; \
    unzip -o httpx.zip httpx -d /usr/local/bin; \
    ( curl -fsSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${GOARCH}.zip" \
      && unzip -o nuclei.zip nuclei -d /usr/local/bin ) || echo "WARN: nuclei install failed"; \
    ( curl -fsSL -o ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${GOARCH}.tar.gz" \
      && tar -xzf ffuf.tar.gz -C /usr/local/bin ffuf ) || echo "WARN: ffuf install failed"; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/httpx; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/ffuf 2>/dev/null || true; \
    rm -f /tmp/*.zip /tmp/*.tar.gz; \
    subfinder -version; dnsx -version; httpx -version; nuclei -version || true; ffuf -V || true

# Extra recon binaries (best-effort, latest release): katana (crawler), naabu
# (fast port scanner) and dalfox (XSS). A failed download just marks the tool
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
    katana -version || true; naabu -version || true; dalfox --version || true

# Curated SecLists wordlists for ffuf content discovery (best-effort downloads;
# a moved URL must not fail the build). Names are friendly for the UI picker.
RUN mkdir -p /usr/share/wordlists; \
    SL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content"; \
    curl -fsSL -o /usr/share/wordlists/quick-hits.txt        "$SL/quickhits.txt"                 || true; \
    curl -fsSL -o /usr/share/wordlists/common.txt            "$SL/common.txt"                    || true; \
    curl -fsSL -o /usr/share/wordlists/raft-small-words.txt  "$SL/raft-small-words.txt"          || true; \
    curl -fsSL -o /usr/share/wordlists/directories-medium.txt "$SL/DirBuster-2007_directory-list-2.3-small.txt" || true; \
    curl -fsSL -o /usr/share/wordlists/api-endpoints.txt     "$SL/api/api-seen-in-wild.txt"      || true; \
    if [ ! -s /usr/share/wordlists/common.txt ]; then \
      printf 'admin\nlogin\napi\nrobots.txt\n.git/HEAD\nbackup\ntest\n.env\nadmin.php\n' > /usr/share/wordlists/common.txt; \
    fi

# Payload lists for the Replay Intruder — fuzzing VALUES (usernames, passwords,
# injection payloads, numbers), as opposed to the content-discovery/path lists
# above. Best-effort downloads (a moved URL just skips that list).
RUN SLP="https://raw.githubusercontent.com/danielmiessler/SecLists/master"; \
    curl -fsSL -o /usr/share/wordlists/usernames-top.txt       "$SLP/Usernames/top-usernames-shortlist.txt"                  || true; \
    curl -fsSL -o /usr/share/wordlists/passwords-top.txt       "$SLP/Passwords/Common-Credentials/top-passwords-shortlist.txt" || true; \
    curl -fsSL -o /usr/share/wordlists/passwords-500-worst.txt "$SLP/Passwords/Common-Credentials/500-worst-passwords.txt"   || true; \
    curl -fsSL -o /usr/share/wordlists/sqli.txt                "$SLP/Fuzzing/Databases/SQLi/Generic-SQLi.txt"                || true; \
    curl -fsSL -o /usr/share/wordlists/sqli-auth-bypass.txt    "$SLP/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt"           || true; \
    curl -fsSL -o /usr/share/wordlists/xss.txt                 "$SLP/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt"            || true; \
    curl -fsSL -o /usr/share/wordlists/lfi.txt                 "$SLP/Fuzzing/LFI/LFI-Jhaddix.txt"                           || true; \
    curl -fsSL -o /usr/share/wordlists/command-injection.txt   "$SLP/Fuzzing/command-injection-commix.txt"                  || true; \
    seq 0 9999    > /usr/share/wordlists/numbers-0-9999.txt; \
    seq -w 0 9999 > /usr/share/wordlists/numbers-0000-9999.txt

# Chromium 150.0.7871.46 (the version bookworm-security pinned when this image was
# first built) SIGTRAPs on EVERY headless launch — even about:blank — which silently
# broke the screenshot job. The regression is fixed in the later 150.x security
# patch (150.0.7871.114+). Pull the current bookworm-security chromium as its own
# layer so a rebuild re-fetches the fix without busting the recon-tool layers above.
RUN apt-get update \
  && apt-get install -y --no-install-recommends --only-upgrade chromium chromium-sandbox \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for better layer caching.
COPY package.json package-lock.json* ./
# npm ci = reproducible install from the lockfile (fails if out of sync).
RUN npm ci

COPY . .
COPY docker-entrypoint.sh /usr/local/bin/recon-entrypoint

RUN mkdir -p /data && chown -R node:node /app /data && chmod 0755 /usr/local/bin/recon-entrypoint

EXPOSE 3001

ENTRYPOINT ["recon-entrypoint"]
CMD ["npm", "run", "dev"]
