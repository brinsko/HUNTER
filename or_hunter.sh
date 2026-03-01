#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/venv" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
else
    echo "[!] venv not found. Run ./setup.sh first."
    exit 1
fi
# Elite Open Redirect Hunter - 2026 Hybrid Elite Edition (Upgraded Pipeline)
set -u
set -o pipefail
set -e
ulimit -n 65535 2>/dev/null || true

EVIL="https://evil.com"
EVIL_HOST="evil.com"
NOW=$(date +"%Y%m%d-%H%M%S")
ROOT_DIR=$(pwd)
RUN_DIR="$ROOT_DIR/runs/run-$NOW"
mkdir -p "$RUN_DIR"

# Flags
RESEARCH_MODE=0
ADVANCED_PAYLOADS=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --research) RESEARCH_MODE=1 ;;
        --advanced) ADVANCED_PAYLOADS=1 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
    shift
done

if [[ $RESEARCH_MODE -eq 1 ]]; then echo "[RESEARCH MODE] enabled"; fi
if [[ $ADVANCED_PAYLOADS -eq 1 ]]; then echo "[ADVANCED PAYLOADS] enabled"; fi

# Progress helpers
TOTAL_WORK=1
COMPLETED_WORK=0

update_status() {
    local phase="$1" percent="$2"
    cat > "$RUN_DIR/status.tmp" <<EOF
{"phase": "$phase", "progress": $percent}
EOF
    mv "$RUN_DIR/status.tmp" "$RUN_DIR/status.json" 2>/dev/null || true
}

increment_progress() {
    COMPLETED_WORK=$((COMPLETED_WORK + 1))
    local percent=$((COMPLETED_WORK * 100 / TOTAL_WORK))
    [ "$percent" -gt 100 ] && percent=100
    update_status "$CURRENT_PHASE" "$percent"
}

echo "═══════════════════════════════════════"
echo "[+] Open Redirect Hunter - 2026 Hybrid Elite"
echo "[+] Run dir : $RUN_DIR"
echo "[+] Canary : $EVIL"
echo "═══════════════════════════════════════"

LAN_IP=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
echo "[+] Dashboard : http://$LAN_IP:8787"

# Dashboard management
pkill -f "python3 dashboard.py" 2>/dev/null || true
pkill -f "flask" 2>/dev/null || true
pkill -f "socketio" 2>/dev/null || true
sleep 1
export HUNT_RUN_DIR="$RUN_DIR"
nohup python3 dashboard.py > "$RUN_DIR/dashboard.log" 2>&1 &
DASH_PID=$!
sleep 2

if ! ps -p $DASH_PID >/dev/null; then
    echo "[!] Dashboard failed. Check $RUN_DIR/dashboard.log"
    cat "$RUN_DIR/dashboard.log"
    exit 1
fi

> "$RUN_DIR/status.json" 2>/dev/null || true
> "$ROOT_DIR/finaloutput.txt" 2>/dev/null || true
update_status "Initializing" 1

trap 'echo -e "\n[+] Stopping..."; kill $DASH_PID 2>/dev/null; pkill -f "python3 dashboard.py" 2>/dev/null; sleep 1; exit 0' INT TERM EXIT

cd "$RUN_DIR" || exit 1

# PHASE 1: Subdomain Enumeration (Smart: only for root domains)
CURRENT_PHASE="Subdomain Enumeration"
echo "[1] Enumerating subdomains (smart mode)..."
TOTAL_WORK=$(wc -l < ../../domains.txt 2>/dev/null || echo 1)
[ "$TOTAL_WORK" -eq 0 ] && TOTAL_WORK=1
COMPLETED_WORK=0

: > raw_subs.txt
while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    dot_count=$(echo "$domain" | awk -F. '{print NF-1}')
    if [ "$dot_count" -le 1 ]; then  # Root domain: enumerate subs
        subfinder -d "$domain" -silent >> raw_subs.txt 2>/dev/null || true
        amass enum -passive -d "$domain" -silent >> raw_subs.txt 2>/dev/null || true
    else  # Subdomain: add directly
        echo "$domain" >> raw_subs.txt
    fi
    increment_progress
done < ../../domains.txt

sort -u raw_subs.txt > successful.txt

# PHASE 2: Alive Probing
CURRENT_PHASE="Alive Probing"
update_status "$CURRENT_PHASE" 20
httpx -l successful.txt -silent -status-code -o live.txt 2>/dev/null || touch live.txt
cp live.txt ../../subdomains.txt 2>/dev/null || true
touch ../../subdomains.txt 2>/dev/null || true

# PHASE 3: Passive URL Collection
CURRENT_PHASE="Passive URL Collection"
update_status "$CURRENT_PHASE" 30
cat live.txt | gau > urls.txt 2>/dev/null || touch urls.txt
cat live.txt | waybackurls >> urls.txt 2>/dev/null || true
sort -u urls.txt -o urls.txt

# PHASE 4: Clean & Normalize
CURRENT_PHASE="Cleaning URLs"
update_status "$CURRENT_PHASE" 40
cat urls.txt | uro > clean_urls.txt 2>/dev/null || touch clean_urls.txt

# PHASE 5: Extract Parameterized URLs (initial)
grep "=" clean_urls.txt > param_urls.txt 2>/dev/null || touch param_urls.txt

# PHASE 6: Active Crawling
CURRENT_PHASE="Crawling"
update_status "$CURRENT_PHASE" 50
katana -list live.txt -o crawl.txt 2>/dev/null || touch crawl.txt
cat urls.txt crawl.txt | sort -u | uro > final_urls.txt 2>/dev/null || touch final_urls.txt

# PHASE: Parameter Discovery with ParamSpider (compatible with older versions)
CURRENT_PHASE="Parameter Discovery"
update_status "$CURRENT_PHASE" 55
: > paramspider_urls.txt

while IFS= read -r line; do
    # Extract clean domain/host from lines like: http://testphp.vulnweb.com [200]
    domain=$(echo "$line" | awk '{print $1}' | sed 's|https\?://||' | cut -d/ -f1 | sed 's/^\s*//;s/\s*$//')
    [ -z "$domain" ] && continue

    output_file="paramspider_${domain//./_}.txt"

    if command -v paramspider >/dev/null; then
        echo "[ParamSpider] Scanning $domain ..."
        paramspider -d "$domain" -s > "$output_file" 2>/dev/null || true
    else
        echo "[!] paramspider not found — skipping $domain"
        continue
    fi

    if [ -s "$output_file" ]; then
        cat "$output_file" >> paramspider_urls.txt
        echo "[+] Found $(wc -l < "$output_file") URLs from $domain"
    else
        echo "[ ] No parameterized URLs found for $domain"
    fi
done < live.txt

# Merge and deduplicate ParamSpider results into final_urls.txt
if [ -s paramspider_urls.txt ]; then
    cat paramspider_urls.txt | sort -u >> final_urls.txt 2>/dev/null || true
    sort -u final_urls.txt -o final_urls.txt
    echo "[ParamSpider] Total unique URLs added: $(wc -l < paramspider_urls.txt)"
else
    echo "[ParamSpider] No additional URLs discovered"
fi

# PHASE 7: Re-extract Parameters
CURRENT_PHASE="Extracting Parameters"
update_status "$CURRENT_PHASE" 60
grep "=" final_urls.txt > param_urls.txt 2>/dev/null || touch param_urls.txt

# PHASE 8: Parameter Intelligence (with unfurl fallback)
CURRENT_PHASE="Parameter Analysis"
update_status "$CURRENT_PHASE" 62

if command -v unfurl >/dev/null; then
    echo "[+] Using unfurl to extract parameter keys..."
    cat param_urls.txt | unfurl keys | sort -u > param_keys.txt 2>/dev/null || touch param_keys.txt
else
    echo "[!] unfurl not found → using basic sed/cut fallback for param keys"
    cat param_urls.txt \
        | grep -oP '(?<=\?)[^#]+' \
        | tr '&' '\n' \
        | cut -d '=' -f1 \
        | grep -v '^$' \
        | sort -u > param_keys.txt 2>/dev/null || touch param_keys.txt
fi

# PHASE 9: Smart Redirect Filtering
CURRENT_PHASE="Redirect Filtering"
update_status "$CURRENT_PHASE" 65
grep -i -f ../../redirect_params.txt param_keys.txt > found_redirect_params.txt 2>/dev/null || touch found_redirect_params.txt
grep -i -f found_redirect_params.txt param_urls.txt > redirect_urls.txt 2>/dev/null || touch redirect_urls.txt

# PHASE 10: Pre-Testing
CURRENT_PHASE="Pre-Testing"
update_status "$CURRENT_PHASE" 70
cat redirect_urls.txt | uro > redirect_clean.txt 2>/dev/null || touch redirect_clean.txt
cat redirect_clean.txt | qsreplace "https://evil.com" > redirect_test.txt 2>/dev/null || touch redirect_test.txt
cat redirect_test.txt | httpx -status-code -location -silent > quick_check.txt 2>/dev/null || touch quick_check.txt

# PHASE 11: Strict Validation
CURRENT_PHASE="Strict Validation"
update_status "$CURRENT_PHASE" 75
if [ -s redirect_clean.txt ]; then
    echo "[+] Strict validation (finder.py)..."
    EXTRA_ARGS=""
    [[ $RESEARCH_MODE -eq 1 ]] && EXTRA_ARGS="--research"
    [[ $ADVANCED_PAYLOADS -eq 1 ]] && EXTRA_ARGS="$EXTRA_ARGS --advanced"
    python3 ../../finder.py redirect_clean.txt "$EVIL" $EXTRA_ARGS
    cp confirmed_redirects.txt successful.txt 2>/dev/null || touch successful.txt
    touch ../../finaloutput.txt 2>/dev/null || true
    sleep 1.2
else
    echo "No redirect URLs found."
    touch successful.txt
fi

# PHASE 12: Nuclei
CURRENT_PHASE="Nuclei Scan"
update_status "$CURRENT_PHASE" 85
httpx -l live.txt -silent 2>/dev/null | nuclei -silent \
    -t ~/nuclei-templates/http/vulnerabilities/generic/open-redirect*.yaml \
    -c 25 -o nuclei.txt || true
touch ../../finaloutput.txt 2>/dev/null || true

# FFUF
CURRENT_PHASE="FFUF Fuzzing"
update_status "$CURRENT_PHASE" 90
: > successful_ffuf.txt
if command -v ffuf >/dev/null && [ -s ../../redirect_params.txt ] && [ -s ../../loxs/payloads/or.txt ]; then
    cat param_urls.txt | gf redirect | uro | sort -u > redirect_endpoints.txt 2>/dev/null
    if [ -s redirect_endpoints.txt ]; then
        while IFS= read -r base_url; do
            [ -z "$base_url" ] && continue
            ffuf -w ../../redirect_params.txt:PARAM \
                 -w ../../loxs/payloads/or.txt:PAYLOAD \
                 -u "${base_url}?PARAM=PAYLOAD" \
                 -mc 301,302,303,307,308 \
                 -ac -t 20 -of csv -o tmp.csv -silent || true
            if [ -s tmp.csv ]; then
                awk -F',' 'NR>1 {print $1}' tmp.csv | while IFS= read -r u; do
                    final=$(curl -L -s -o /dev/null -w "%{url_effective}" --max-time 8 "$u" 2>/dev/null || echo "")
                    final_host=$(echo "$final" | awk -F/ '{print $3}' | sed 's/\.$//')
                    if [[ "$final_host" == "$EVIL_HOST" || "$final_host" == *".$EVIL_HOST" ]]; then
                        echo "$u" >> successful_ffuf.txt
                    fi
                done
            fi
        done < redirect_endpoints.txt
    fi
fi
touch ../../finaloutput.txt 2>/dev/null || true

# Final Merge
CURRENT_PHASE="Finalizing"
update_status "$CURRENT_PHASE" 95
cat successful.txt successful_ffuf.txt nuclei.txt 2>/dev/null \
    | grep -E '^https?://' | sort -u > ../../finaloutput.txt

touch ../../finaloutput.txt 2>/dev/null || true
sleep 1.3
ln -sf ../../finaloutput.txt finaloutput.txt 2>/dev/null || true

update_status "Hunt Complete" 100

COUNT=$(wc -l < ../../finaloutput.txt 2>/dev/null || echo 0)
echo "Confirmed Open Redirects: $COUNT"
echo "Output File: $ROOT_DIR/finaloutput.txt"
echo "═══════════════════════════════════════"
sleep 1
wait $DASH_PID 2>/dev/null || true
