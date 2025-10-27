#!/usr/bin/env bash
# bb_recon_with_active_ingest.sh
# Passive recon + optional ACTIVE-RESULTS INGEST (script will NOT run active scans)
# - Passive flow: subdomains (crt.sh + optional tools), live probe, headers, TLS, screenshots, Shodan (optional), CVE hints
# - Active-results ingest: parse user-provided outputs (nmap.gnmap, nuclei.json, nikto.txt, custom) and embed summaries in HTML
#
# IMPORTANT:
#  - This script WILL NOT run nmap/nuclei/nikto/etc. for you.
#  - To include active scan results, run those tools separately (per your authorization), produce output files,
#    then provide the file paths when prompted. The script will parse and include them.
#  - Only use active scanning tools against systems you are explicitly authorized to test.
#
set -euo pipefail
IFS=$'\n\t'

# ---------------- Config ----------------
THREADS=20
CURL_TIMEOUT=8
OUTROOT="bb_run_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTROOT"

# Detect tools
has(){ command -v "$1" >/dev/null 2>&1; }
HAS_HTTPX=0; HAS_GOWITNESS=0; HAS_JQ=0
has httpx && HAS_HTTPX=1
has gowitness && HAS_GOWITNESS=1
has jq && HAS_JQ=1

SHODAN_API_KEY="${SHODAN_API_KEY:-}"

log(){ printf '[%s] %s\n' "$(date +'%H:%M:%S')" "$*"; }

normalize_domain(){ local s="$1"; s="${s#http://}"; s="${s#https://}"; s="${s%%/*}"; echo "$s"; }
safe_mkdir(){ mkdir -p "$1"; }

# ---------------- Safety gate ----------------
echo "LEGAL: Only run this script against domains you have explicit written permission to test."
read -r -p "Type EXACTLY 'I HAVE_PERMISSION' to proceed: " CONF
if [[ "$CONF" != "I HAVE_PERMISSION" ]]; then
  echo "Permission phrase not provided. Exiting."
  exit 1
fi

# ---------------- Input modes ----------------
echo
echo "Input mode:"
echo "  1) Manual: type domains (one per line, blank to finish)"
echo "  2) File: path to file with domains (one per line)"
read -r -p "Choose 1 or 2: " MODE
TARGETS=()
if [[ "$MODE" == "1" ]]; then
  echo "Enter domains (blank line to finish):"
  while true; do
    read -r line
    [[ -z "$line" ]] && break
    TARGETS+=("$(normalize_domain "$line")")
  done
else
  read -r -p "Enter path to file with domains: " FILEPATH
  if [[ ! -f "$FILEPATH" ]]; then echo "File not found"; exit 1; fi
  mapfile -t raw < "$FILEPATH"
  for d in "${raw[@]}"; do [[ -n "${d// /}" ]] && TARGETS+=("$(normalize_domain "$d")"); done
fi

if [ ${#TARGETS[@]} -eq 0 ]; then echo "No targets provided. Exiting."; exit 1; fi

read -r -p "Output directory name (enter to use '$OUTROOT'): " OUTDIRUSER
if [[ -n "$OUTDIRUSER" ]]; then OUTROOT="$OUTDIRUSER"; fi
mkdir -p "$OUTROOT"

log "Output root: $OUTROOT"
log "Optional tools detected: httpx=$HAS_HTTPX gowitness=$HAS_GOWITNESS jq=$HAS_JQ"
[[ -n "$SHODAN_API_KEY" ]] && log "Shodan: enabled"

# ---------------- Passive functions (same style as before) ----------------
enumerate_subs_passive(){
  local domain="$1" out="$2"
  : > "$out"
  log "crt.sh -> $domain"
  if has curl; then
    if has jq; then
      curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' >> "$out" || true
    else
      curl -s "https://crt.sh/?q=%25.$domain&output=json" | sed -n 's/.*"name_value":"\([^"]*\)".*/\1/p' | sed 's/\*\.//g' >> "$out" || true
    fi
  fi
  echo "$domain" >> "$out"
  sort -u "$out" -o "$out" || true
}

probe_live_http(){
  local infile="$1" outfile="$2"
  : > "$outfile"
  if [[ "$HAS_HTTPX" -eq 1 ]]; then
    httpx -l "$infile" -silent -threads "$THREADS" -status-code -o "$outfile.httpx" 2>/dev/null || true
    awk '{print $1}' "$outfile.httpx" | sort -u > "$outfile" || true
  else
    while read -r host; do
      for scheme in https http; do
        url="${scheme}://${host}"
        if curl -s --max-time $CURL_TIMEOUT -I -L "$url" >/dev/null 2>&1; then
          echo "$url" >> "$outfile"
          break
        fi
      done
    done < "$infile"
    sort -u "$outfile" -o "$outfile" || true
  fi
}

collect_artifacts(){
  local livefile="$1" base="$2"
  mkdir -p "$base/artifacts"
  while read -r url; do
    [ -z "$url" ] && continue
    safe=$(echo "$url" | sed 's#[:/]*#_#g')
    targ="$base/artifacts/$safe"
    mkdir -p "$targ"
    # robots/sitemap/headers/homepage/cert (passive)
    curl -s --max-time $CURL_TIMEOUT -L "${url%/}/robots.txt" -o "$targ/robots.txt" || true
    curl -s --max-time $CURL_TIMEOUT -L "${url%/}/sitemap.xml" -o "$targ/sitemap.xml" || true
    curl -s --max-time $CURL_TIMEOUT -I -L "$url" -o "$targ/headers.txt" || true
    curl -s --max-time $CURL_TIMEOUT -L "$url" -o "$targ/homepage.html" || true
    if [[ "$url" =~ ^https:// ]]; then
      host=$(echo "$url" | sed -E 's#https?://([^/]+).*#\1#')
      echo | openssl s_client -connect "${host}:443" -servername "$host" 2>/dev/null | openssl x509 -noout -dates > "$targ/cert_dates.txt" 2>/dev/null || true
    fi
  done < "$livefile"
}

take_screenshots(){
  local livefile="$1" base="$2"
  mkdir -p "$base/screenshots"
  if [[ "$HAS_GOWITNESS" -eq 1 ]]; then
    log "Capturing screenshots with gowitness (file mode)"
    gowitness file -f "$livefile" --destination "$base/screenshots" --timeout 5 >/dev/null 2>&1 || true
  else
    log "gowitness not detected; skipping screenshots"
  fi
}

# Passive CVE hints (same approach)
passive_cve_hints(){
  local artifacts_dir="$1" out="$2"
  : > "$out"
  for hdr in "$artifacts_dir"/*/headers.txt; do
    [ -f "$hdr" ] || continue
    urlname=$(basename "$(dirname "$hdr")")
    server=$(awk 'BEGIN{IGNORECASE=1} /^Server:/{print; exit}' "$hdr" || true)
    xpby=$(awk 'BEGIN{IGNORECASE=1} /^X-Powered-By:/{print; exit}' "$hdr" || true)
    candidate=""
    if [[ -n "$server" && "$server" =~ ([A-Za-z0-9_\-]+)\/([0-9\.]+) ]]; then
      prod="${BASH_REMATCH[1]}"; ver="${BASH_REMATCH[2]}"
      candidate="$prod $ver"
    elif [[ -n "$xpby" && "$xpby" =~ ([A-Za-z0-9_\-]+)\/([0-9\.]+) ]]; then
      prod="${BASH_REMATCH[1]}"; ver="${BASH_REMATCH[2]}"
      candidate="$prod $ver"
    fi
    if [[ -n "$candidate" ]]; then
      echo "$urlname | detected: $candidate" >> "$out"
      if has searchsploit; then
        searchsploit "$prod $ver" | sed -n '1,6p' >> "$out" || true
      else
        echo "Manual check suggestion: searchsploit \"$candidate\" or check NVD" >> "$out"
      fi
      echo "" >> "$out"
    fi
  done
}

# Heuristic priority classification (same idea)
heuristic_priority(){
  local base="$1" livefile="$2" out="$3"
  : > "$out"
  while read -r url; do
    [ -z "$url" ] && continue
    hdr="$base/artifacts/$(echo "$url" | sed 's#https\?://##; s#/$##')/headers.txt"
    hp="$base/artifacts/$(echo "$url" | sed 's#https\?://##; s#/$##')/homepage.html"
    score=0; reasons=()
    if [ -f "$hp" ] && grep -Ei 'wp-admin|wp-login|login|admin|api_key|token|aws_access' "$hp" >/dev/null 2>&1; then
      score=$((score+30)); reasons+=("sensitive token/admin strings on page")
    fi
    if [ -f "$hdr" ] && grep -Ei 'Server:.*/[0-9]' "$hdr" >/dev/null 2>&1; then
      score=$((score+8)); reasons+=("server header version exposed")
    fi
    if [ -f "$hdr" ] && ! grep -Ei 'Strict-Transport-Security|Content-Security-Policy' "$hdr" >/dev/null 2>&1; then
      score=$((score+5)); reasons+=("missing HSTS/CSP")
    fi
    if [ "$score" -ge 25 ]; then pr="HIGH"; elif [ "$score" -ge 8 ]; then pr="MEDIUM"; elif [ "$score" -gt 0 ]; then pr="LOW"; else pr="INFO"; fi
    printf "%s | score=%d | %s | %s\n" "$url" "$score" "$pr" "$(IFS='; '; echo "${reasons[*]:-none}")" >> "$out"
  done < "$livefile"
  sort -t '|' -k2 -nr "$out" -o "$out" || true
}

# ---------------- Active-results ingest helpers (PARSERS) ----------------
# NOTE: these parse files YOU provide. Script will NOT execute scans.
parse_nmap_gnmap(){
  # expects a gnmap file path
  local gnmap="$1" out="$2"
  : > "$out"
  if [[ ! -f "$gnmap" ]]; then echo "Nmap gnmap not found: $gnmap"; return; fi
  # GNMAP lines example: Host: 1.2.3.4 ()    Ports: 80/open/tcp//http///,443/open/tcp//https///    Status: Up
  awk -F'Ports: ' '/Ports: / { host=$2=""; split($0,a,"Host: "); h=a[2]; split(h,h2," "); hostip=h2[1]; ports=$2; split(ports,p,","); for(i in p){ if(p[i] ~ /open/){ gsub(/^ +| +$/,"",p[i]); print hostip " | " p[i]; } } }' "$gnmap" \
    | sed 's/\/open\/tcp\/\/.*//g' | sort -u > "$out" || true
  # produce a summary
  echo "Nmap GNMAP parse summary: $(wc -l < "$out") open-service-lines" >> "$out"
}

parse_nuclei_json(){
  # expects nuclei JSON lines file (each line is JSON) or JSON array
  local nj="$1" out="$2"
  : > "$out"
  if [[ ! -f "$nj" ]]; then echo "Nuclei output not found: $nj"; return; fi
  # Using jq if available
  if has jq; then
    jq -r 'if type=="array" then .[] else . end | "\(.info.severity) | \(.info.name) | \(.host) | \(.matched)\n"' "$nj" 2>/dev/null | sed '/^null/d' >> "$out" || true
  else
    # crude grep fallback: extract severity/name/host
    grep -E '"info":|"host":' "$nj" | sed -n '1,200p' >> "$out" || true
  fi
  echo "Nuclei findings summary: $(wc -l < "$out") lines" >> "$out"
}

parse_nikto_text(){
  local nikto="$1" out="$2"
  : > "$out"
  if [[ ! -f "$nikto" ]]; then echo "Nikto file not found: $nikto"; return; fi
  # Nikto plain text - pull interesting lines
  grep -Ei 'OSVDB|+|Server:|favicon|Found:|Interesting' "$nikto" | sed -n '1,200p' >> "$out" || true
  echo "Nikto summary may contain: $(wc -l < "$out") lines" >> "$out"
}

# ---------------- HTML report generator (includes active-results if present) ----------------
generate_report(){
  local base="$1" domain="$2" html="$base/report.html"
  log "Generating HTML report for $domain"
  cat > "$html" <<HTML
<!doctype html>
<html><head><meta charset="utf-8"><title>Recon Report - $domain</title>
<style>body{font-family:Arial;margin:18px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#111;color:#fff}tr:nth-child(even){background:#f9f9f9}.high{background:#ffcccc}.medium{background:#fff2cc}.low{background:#e6f7ff}.thumb{max-width:240px;max-height:140px}</style>
</head><body>
<h1>Recon Report: $domain</h1>
<p>Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ") (UTC)</p>

<h2>Summary</h2>
<ul>
<li>Subdomains: $(wc -l < "$base/subdomains.txt" 2>/dev/null || echo 0)</li>
<li>Live hosts: $(wc -l < "$base/live.txt" 2>/dev/null || echo 0)</li>
<li>Priority entries: $(wc -l < "$base/priority.txt" 2>/dev/null || echo 0)</li>
</ul>

<h2>Priority summary</h2>
<table><tr><th>Host</th><th>Score</th><th>Priority</th><th>Reasons</th><th>Screenshot</th></tr>
HTML

  while read -r line; do
    [[ -z "$line" ]] && continue
    host=$(echo "$line" | awk -F'|' '{print $1}' | xargs)
    score=$(echo "$line" | awk -F'|' '{print $2}' | sed 's/score=//g' | xargs)
    pr=$(echo "$line" | awk -F'|' '{print $3}' | xargs)
    reasons=$(echo "$line" | awk -F'|' '{print $4}' | xargs)
    cls="info"; [ "$pr" = "HIGH" ] && cls="high"; [ "$pr" = "MEDIUM" ] && cls="medium"; [ "$pr" = "LOW" ] && cls="low"
    thumb=""
    if [ -d "$base/screenshots" ]; then
      candidate="$(ls -1 "$base/screenshots" 2>/dev/null | grep -i "$(echo "$host" | sed 's#https\?://##; s#[:/]##g' )" | head -n1 || true)"
      [ -z "$candidate" ] && candidate="$(ls -1 "$base/screenshots" 2>/dev/null | head -n1 || true)"
      [ -n "$candidate" ] && thumb="screenshots/$candidate"
    fi
    if [ -n "$thumb" ]; then screenshot_html="<a href=\"$thumb\" target=\"_blank\"><img src=\"$thumb\" class=\"thumb\"></a>"; else screenshot_html="(no screenshot)"; fi

    cat >> "$html" <<ROW
<tr class="$cls"><td><a href="$host" target="_blank">$host</a></td><td>$score</td><td>$pr</td><td>$reasons</td><td>$screenshot_html</td></tr>
ROW
  done < "$base/priority.txt"

  cat >> "$html" <<HTML
</table>

<h2>Passive CVE hints</h2>
<pre>$(sed -n '1,200p' "$base/passive_cve_hints.txt" 2>/dev/null || echo "None")</pre>

<h2>Active scan summaries (user-supplied)</h2>
<ul>
HTML

  # list active summaries if present
  for file in "$base/active_parsed_"* 2>/dev/null; do
    [ -f "$file" ] || continue
    name=$(basename "$file")
    echo "<li><a href=\"$name\">$name</a></li>" >> "$html"
  done

cat >> "$html" <<HTML
</ul>

<h2>Artifacts</h2>
<ul>
<li><a href="subdomains.txt">subdomains.txt</a></li>
<li><a href="live.txt">live.txt</a></li>
<li><a href="artifacts/headers.summary">headers.summary</a></li>
<li><a href="artifacts/certs.summary">certs.summary</a></li>
<li><a href="passive_cve_hints.txt">passive_cve_hints.txt</a></li>
</ul>

<p><em>Note: Active scan results are included only if you provided them. This script never runs active scans by itself.</em></p>
</body></html>
HTML

  log "Report generated: $html"
}

# ---------------- Main flow ----------------
for TARGET in "${TARGETS[@]}"; do
  DOMAIN=$(normalize_domain "$TARGET")
  BASE="$OUTROOT/$DOMAIN"
  safe_mkdir "$BASE"

  # Passive
  SUBS="$BASE/subdomains.txt"
  LIVE="$BASE/live.txt"
  enumerate_subs_passive "$DOMAIN" "$SUBS"
  probe_live_http "$SUBS" "$LIVE"
  collect_artifacts "$LIVE" "$BASE"
  take_screenshots "$LIVE" "$BASE"
  passive_cve_hints "$BASE/artifacts" "$BASE/passive_cve_hints.txt"
  heuristic_priority "$BASE" "$LIVE" "$BASE/priority.txt"

  # ---------------- Active ingest prompt ----------------
  echo
  echo "---------- ACTIVE RESULTS INGEST (OPTIONAL) ----------"
  echo "This script WILL NOT run active scans for you."
  echo "If you ran active scans separately and want to include their outputs in the report,"
  echo "provide file paths below. Leave blank to skip ingest."
  echo "Accepted types (examples):"
  echo "  - Nmap GNMAP output (e.g., nmap -oG output.gnmap) "
  echo "  - Nuclei JSONL or JSON (each line JSON or array) "
  echo "  - Nikto plain text output "
  echo
  read -r -p "Enter path to nmap .gnmap file (or press ENTER to skip): " NMAP_GNMAP
  read -r -p "Enter path to nuclei json output (or press ENTER to skip): " NUCLEI_JSON
  read -r -p "Enter path to nikto text output (or press ENTER to skip): " NIKTO_TXT

  # second confirmation (must type to proceed with ingest)
  if [[ -n "$NMAP_GNMAP" || -n "$NUCLEI_JSON" || -n "$NIKTO_TXT" ]]; then
    echo
    echo "You have requested to ingest active scan results. Make sure you only ingested scans you were authorized to run."
    read -r -p "Type EXACTLY 'I WILL RUN ACTIVE TOOLS MYSELF' to allow parsing of your files: " CONF2
    if [[ "$CONF2" != "I WILL RUN ACTIVE TOOLS MYSELF" ]]; then
      echo "Active ingest confirmation not provided. Skipping active ingest."
      NMAP_GNMAP=""; NUCLEI_JSON=""; NIKTO_TXT=""
    fi
  fi

  # parse provided files (no scans executed)
  if [[ -n "$NMAP_GNMAP" ]]; then
    parse_nmap_gnmap "$NMAP_GNMAP" "$BASE/active_parsed_nmap.txt"
  fi
  if [[ -n "$NUCLEI_JSON" ]]; then
    parse_nuclei_json "$NUCLEI_JSON" "$BASE/active_parsed_nuclei.txt"
  fi
  if [[ -n "$NIKTO_TXT" ]]; then
    parse_nikto_text "$NIKTO_TXT" "$BASE/active_parsed_nikto.txt"
  fi

  # copy artifacts for HTML links (some may already exist)
  cp -f "$SUBS" "$BASE/subdomains.txt" || true
  cp -f "$LIVE" "$BASE/live.txt" || true

  # generate report (includes active_parsed_* files if present)
  generate_report "$BASE" "$DOMAIN"

  log "Completed target: $DOMAIN; files under $BASE"
done

log "ALL DONE. Master output: $OUTROOT"
echo "Open the generated report(s):"
for f in "$OUTROOT"/*/report.html; do echo " - $f"; done
echo "Reminder: Active scans must be run by you separately and only with authorization."