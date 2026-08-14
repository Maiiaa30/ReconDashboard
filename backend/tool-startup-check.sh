#!/bin/sh
set -u

# Log and verify the exact scanner set on every container start. Updating a
# running container would make deployments non-reproducible, so updates remain
# pinned at image build time while every restart detects an incomplete image.
tools="subfinder dnsx httpx nuclei ffuf katana naabu dalfox nmap sslscan sqlmap chromium dig whois"
required="$tools"
missing_required=""

for tool in $tools; do
  if command -v "$tool" >/dev/null 2>&1; then
    case "$tool" in
      subfinder|dnsx|httpx|nuclei|katana|naabu) output="$($tool -version 2>&1 | grep -m1 -E 'Current [Vv]ersion|Engine Version' || true)" ;;
      ffuf) output="$(ffuf -V 2>&1 | head -n1)" ;;
      dalfox|sslscan) output="$($tool --version 2>&1 | head -n1)" ;;
      nmap) output="$(nmap --version 2>&1 | head -n1)" ;;
      sqlmap) output="$(sqlmap --version 2>&1 | head -n1)" ;;
      chromium) output="$(chromium --version 2>&1 | head -n1)" ;;
      dig) output="$(dig -v 2>&1 | head -n1)" ;;
      whois) output="$(whois --version 2>&1 | head -n1)" ;;
    esac
    clean="$(printf '%s' "$output" | sed 's/\x1b\[[0-9;]*m//g')"
    printf 'tool-check name=%s status=available version="%s"\n' "$tool" "$clean"
  else
    printf 'tool-check name=%s status=missing\n' "$tool" >&2
    case " $required " in *" $tool "*) missing_required="$missing_required $tool" ;; esac
  fi
done

if [ -n "$missing_required" ]; then
  printf 'required discovery tools missing:%s\n' "$missing_required" >&2
  exit 1
fi
