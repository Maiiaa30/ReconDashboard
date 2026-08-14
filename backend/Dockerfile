FROM node:22-bookworm-slim

# --- System + recon tooling --------------------------------------------------
# Build dependencies, distro utilities, and runtime libraries.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       python3 make g++ git zlib1g-dev libssl-dev libssh2-1-dev ca-certificates curl unzip nmap whois gosu \
       dnsutils iputils-ping sslscan sqlmap libpcap0.8 chromium chromium-sandbox fonts-liberation \
  && rm -rf /var/lib/apt/lists/*

# Where headless Chromium lives, for the screenshot job.
ENV CHROMIUM_PATH=/usr/bin/chromium

# Pinned prebuilt release binaries. Keep these arguments after the system
# packages so a scanner version bump does not invalidate the large apt layer.
ARG SUBFINDER_VERSION=2.15.0
ARG DNSX_VERSION=1.3.0
ARG HTTPX_VERSION=1.10.0
ARG NUCLEI_VERSION=3.11.1
ARG FFUF_VERSION=2.2.1
ARG KATANA_VERSION=1.7.0
ARG NAABU_VERSION=2.6.1
ARG DALFOX_VERSION=3.2.1
ARG NMAP_VERSION=7.99
ARG SQLMAP_VERSION=1.10
ARG SSLSCAN_VERSION=2.2.2

# The continuous-discovery pipeline depends on subfinder, dnsx, and httpx. Keep
# their versions deterministic and fail the image build if any core binary is
# missing; a deploy must never produce a superficially healthy but incomplete
# scanner image.
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
    curl --retry 4 --retry-all-errors -fsSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${GOARCH}.zip"; \
    unzip -o nuclei.zip nuclei -d /usr/local/bin; \
    curl --retry 4 --retry-all-errors -fsSL -o ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${GOARCH}.tar.gz"; \
    tar -xzf ffuf.tar.gz -C /usr/local/bin ffuf; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/dnsx /usr/local/bin/httpx /usr/local/bin/nuclei /usr/local/bin/ffuf; \
    rm -f /tmp/*.zip /tmp/*.tar.gz; \
    subfinder -version; dnsx -version; httpx -version; nuclei -version; ffuf -V

# Extra scanners are pinned too, avoiding GitHub API rate limits and preventing
# an upstream release from changing an otherwise identical image build.
RUN set -ux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) GOARCH=amd64; DALARCH=x86_64 ;; arm64) GOARCH=arm64; DALARCH=aarch64 ;; *) echo "unsupported architecture: $arch" >&2; exit 1 ;; esac; \
    cd /tmp; \
    curl --retry 4 --retry-all-errors -fsSL -o katana.zip "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${GOARCH}.zip"; \
    unzip -o katana.zip katana -d /usr/local/bin; \
    curl --retry 4 --retry-all-errors -fsSL -o naabu.zip "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${GOARCH}.zip"; \
    unzip -o naabu.zip naabu -d /usr/local/bin; \
    curl --retry 4 --retry-all-errors -fsSL -o dalfox.tar.gz "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-${DALARCH}.tar.gz"; \
    tar -xzf dalfox.tar.gz -C /usr/local/bin --wildcards --transform='s#.*/##' '*/dalfox'; \
    chmod +x /usr/local/bin/katana /usr/local/bin/naabu /usr/local/bin/dalfox; \
    rm -f /tmp/*.zip /tmp/*.tar.gz; \
    katana -version; naabu -version; dalfox --version

# Debian Bookworm intentionally ships older stable packages for these tools.
# Install the audited upstream releases over them while retaining the distro
# packages as runtime dependency providers and emergency fallbacks.
RUN set -ux; \
    cd /tmp; \
    curl --retry 10 --retry-all-errors --continue-at - --max-time 180 -fsSL -o nmap.tgz "https://nmap.org/dist/nmap-${NMAP_VERSION}.tgz"; \
    tar -xzf nmap.tgz; \
    cd "nmap-${NMAP_VERSION}"; \
    ./configure --without-zenmap; \
    make -j2; \
    make install; \
    cd /tmp; \
    rm -rf /tmp/nmap*; \
    nmap --version | head -n 1 | grep -F "Nmap version ${NMAP_VERSION} "

RUN set -ux; \
    cd /tmp; \
    curl --retry 4 --retry-all-errors -fsSL -o sqlmap.zip "https://github.com/sqlmapproject/sqlmap/archive/refs/tags/${SQLMAP_VERSION}.zip"; \
    unzip -q sqlmap.zip; \
    rm -rf /opt/sqlmap; \
    mv "sqlmap-${SQLMAP_VERSION}" /opt/sqlmap; \
    sed -i '1s|python$|python3|' /opt/sqlmap/sqlmap.py; \
    ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap; \
    rm -f /tmp/sqlmap.zip; \
    sqlmap --version

# SSLScan 2.2+ requires OpenSSL 3.5, newer than Bookworm. Its supported static
# build bundles the compatible OpenSSL libraries and avoids changing system TLS.
RUN set -ux; \
    cd /tmp; \
    curl --retry 4 --retry-all-errors -fsSL -o sslscan.zip "https://github.com/rbsec/sslscan/archive/refs/tags/${SSLSCAN_VERSION}.zip"; \
    unzip -q sslscan.zip; \
    cd "sslscan-${SSLSCAN_VERSION}"; \
    make -j2 static; \
    install -m 0755 sslscan /usr/local/bin/sslscan; \
    cd /tmp; \
    rm -rf /tmp/sslscan*; \
    sslscan --version

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
COPY tool-startup-check.sh /usr/local/bin/tool-startup-check

RUN mkdir -p /data && chown -R node:node /app /data \
  && chmod 0755 /usr/local/bin/recon-entrypoint /usr/local/bin/tool-startup-check

EXPOSE 3001

ENTRYPOINT ["recon-entrypoint"]
CMD ["npm", "run", "dev"]
