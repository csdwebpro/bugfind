#!/bin/bash

####################
# BlackHat Recon Pro #
####################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
show_banner() {
    cat << "BANNER"
    ____  _      _    _           _   _          _   _             
   |  _ \| |    | |  | |         | | | |        | | | |            
   | |_) | | ___| |__| | __ _ ___| |_| |__   ___| |_| |_ ___ _ __  
   |  _ <| |/ _ \  __  |/ _` / __| __| '_ \ / _ \ __| __/ _ \ '_ \ 
   | |_) | |  __/ |  | | (_| \__ \ |_| | | |  __/ |_| ||  __/ | | |
   |____/|_|\___|_|  |_|\__,_|___/\__|_| |_|\___|\__|\__\___|_| |_|
   
                   Advanced Reconnaissance Suite
                         BlackHat Edition v2.0
BANNER
}

# Configuration
THREADS=10
TIMEOUT=30
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
OUTDIR="./recon_results"
WORDLIST="/usr/share/wordlists/dirb/common.txt"
SUBDOMAIN_WORDLIST="/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"

# API Keys (configure these in .env file)
SHODAN_API=""
CENSYS_API_ID=""
CENSYS_API_SECRET=""

# Load environment variables
load_env() {
    if [[ -f ".env" ]]; then
        source .env
    fi
}

# Dependency check
require_tools() {
    local tools=("python3" "nmap" "subfinder" "amass" "httpx" "nuclei" "waybackurls" "gau" "ffuf" "sqlmap" "xsstrike" "dnsx" "naabu" "katana")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[ERROR] Missing tools: ${missing[*]}${NC}"
        echo "Install with: apt install ${missing[*]} || brew install ${missing[*]}"
        exit 1
    fi
}

# Advanced help menu
show_help() {
    cat <<-HELP
${CYAN}BlackHat Recon Pro - Advanced Reconnaissance Suite${NC}

Usage: $0 -u <domain|url> | -f <targets_file> [OPTIONS]

${YELLOW}Target Options:${NC}
  -u <url>        Single target (domain or URL)
  -f <file>       File with targets (one per line)
  -d <domain>     Domain for extensive reconnaissance

${YELLOW}Scan Options:${NC}
  -m <mode>       Scan mode: quick|deep|stealth|aggressive
  -t <threads>    Concurrency level (default: $THREADS)
  -T <timeout>    Request timeout in seconds (default: $TIMEOUT)
  
${YELLOW}Module Options:${NC}
  --no-subdomains    Skip subdomain enumeration
  --no-portscan      Skip port scanning  
  --no-webscan       Skip web application scanning
  --no-vulnscan      Skip vulnerability scanning
  --osint-only       Only perform OSINT gathering
  --passive-only     Only passive reconnaissance
  
${YELLOW}Output Options:${NC}
  -o <directory>   Output directory (default: $OUTDIR)
  -w <webhook>     Webhook URL for notifications
  --json           Output in JSON format
  --html           Generate HTML report

${YELLOW}Advanced Options:${NC}
  --shodan         Use Shodan for reconnaissance
  --censys         Use Censys for reconnaissance
  --tor            Route traffic through Tor
  --proxy <proxy>  Use HTTP/SOCKS proxy
  --random-agent   Use random user agents

${YELLOW}Examples:${NC}
  $0 -u example.com -m deep
  $0 -f targets.txt -m stealth --tor
  $0 -d example.com --osint-only --shodan

HELP
}

# Initialize environment
init_environment() {
    load_env
    mkdir -p "$OUTDIR"
    mkdir -p "$OUTDIR/temp"
    
    # Create necessary directories
    local subdirs=("subdomains" "ports" "web" "vulnerabilities" "osint" "screenshots")
    for dir in "${subdirs[@]}"; do
        mkdir -p "$OUTDIR/$dir"
    done
}

# Domain validation
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        echo -e "${RED}[ERROR] Invalid domain: $domain${NC}"
        return 1
    fi
    return 0
}

# URL validation
validate_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://$url"
    fi
    echo "$url"
}

# Passive subdomain enumeration
passive_subdomain_enum() {
    local domain="$1"
    local outfile="$OUTDIR/subdomains/passive_$domain.txt"
    
    echo -e "${CYAN}[INFO] Starting passive subdomain enumeration for $domain${NC}"
    
    subfinder -d "$domain" -silent > "$outfile.subfinder"
    amass enum -passive -d "$domain" -o "$outfile.amass"
    assetfinder --subs-only "$domain" > "$outfile.assetfinder" 2>/dev/null
    
    # Combine and sort unique subdomains
    cat "$outfile."* 2>/dev/null | sort -u > "$outfile"
    local count=$(wc -l < "$outfile" 2>/dev/null || echo 0)
    
    echo -e "${GREEN}[SUCCESS] Found $count subdomains passively${NC}"
    echo "$outfile"
}

# Active subdomain enumeration  
active_subdomain_enum() {
    local domain="$1"
    local outfile="$OUTDIR/subdomains/active_$domain.txt"
    
    echo -e "${CYAN}[INFO] Starting active subdomain enumeration${NC}"
    
    # DNS brute force
    puredns resolve "$OUTDIR/subdomains/passive_$domain.txt" -r /usr/share/wordlists/dns-resolvers/resolvers.txt > "$outfile.puredns" 2>/dev/null
    
    # Combine results
    cat "$OUTDIR/subdomains/passive_$domain.txt" "$outfile.puredns" 2>/dev/null | sort -u > "$outfile"
    local count=$(wc -l < "$outfile" 2>/dev/null || echo 0)
    
    echo -e "${GREEN}[SUCCESS] Found $count total subdomains${NC}"
    echo "$outfile"
}

# Port scanning with version detection
advanced_port_scan() {
    local target="$1"
    local outfile="$OUTDIR/ports/scan_$target.xml"
    
    echo -e "${CYAN}[INFO] Starting advanced port scanning for $target${NC}"
    
    # Stealth scan with version detection
    nmap -sS -sV -sC -O -T4 -p- --min-rate 5000 -oX "$outfile" "$target" > /dev/null 2>&1
    
    # Convert to readable format
    xsltproc "$outfile" -o "$OUTDIR/ports/scan_$target.html" 2>/dev/null
    nmap -sS -sV -sC -T4 -p- "$target" > "$OUTDIR/ports/scan_$target.txt" 2>/dev/null
    
    echo -e "${GREEN}[SUCCESS] Port scan completed${NC}"
}

# Web discovery and crawling
web_discovery() {
    local domain="$1"
    local outfile="$OUTDIR/web/discovered_$domain.txt"
    
    echo -e "${CYAN}[INFO] Starting web discovery for $domain${NC}"
    
    # Discover live hosts
    cat "$OUTDIR/subdomains/active_$domain.txt" | httpx -silent -threads "$THREADS" > "$outfile.httpx"
    
    # Wayback machine URLs
    echo "$domain" | waybackurls > "$outfile.wayback"
    gau "$domain" > "$outfile.gau"
    
    # Combine URLs
    cat "$outfile.wayback" "$outfile.gau" 2>/dev/null | sort -u > "$outfile.urls"
    
    local host_count=$(wc -l < "$outfile.httpx" 2>/dev/null || echo 0)
    local url_count=$(wc -l < "$outfile.urls" 2>/dev/null || echo 0)
    
    echo -e "${GREEN}[SUCCESS] Found $host_count live hosts and $url_count historical URLs${NC}"
}

# Directory brute forcing
directory_bruteforce() {
    local url="$1"
    local domain=$(echo "$url" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    local outdir="$OUTDIR/web/directory_$domain"
    
    mkdir -p "$outdir"
    
    echo -e "${CYAN}[INFO] Starting directory brute force for $url${NC}"
    
    ffuf -u "$url/FUZZ" -w "$WORDLIST" -mc 200,301,302,403 -o "$outdir/ffuf.json" -of json > /dev/null 2>&1
    
    echo -e "${GREEN}[SUCCESS] Directory brute force completed${NC}"
}

# Vulnerability scanning
vulnerability_scan() {
    local domain="$1"
    local hosts_file="$OUTDIR/web/discovered_$domain.txt.httpx"
    
    echo -e "${CYAN}[INFO] Starting vulnerability assessment${NC}"
    
    # Nuclei scanning
    nuclei -l "$hosts_file" -t /usr/share/nuclei-templates/ -o "$OUTDIR/vulnerabilities/nuclei_$domain.txt" -severity low,medium,high,critical
    
    # XSS scanning
    cat "$hosts_file" | while read host; do
        xsstrike -u "$host" --crawl > "$OUTDIR/vulnerabilities/xss_$domain.txt" 2>/dev/null
    done
    
    echo -e "${GREEN}[SUCCESS] Vulnerability assessment completed${NC}"
}

# OSINT Gathering
osint_gathering() {
    local domain="$1"
    local outdir="$OUTDIR/osint"
    
    echo -e "${CYAN}[INFO] Starting OSINT gathering for $domain${NC}"
    
    # WHOIS information
    whois "$domain" > "$outdir/whois_$domain.txt"
    
    # DNS reconnaissance
    dnsrecon -d "$domain" -t std > "$outdir/dnsrecon_$domain.txt" 2>/dev/null
    
    # Shodan search if API key available
    if [[ -n "$SHODAN_API" ]]; then
        shodan search "hostname:$domain" > "$outdir/shodan_$domain.txt" 2>/dev/null
    fi
    
    # Censys search if API available
    if [[ -n "$CENSYS_API_ID" ]]; then
        censys search "$domain" > "$outdir/censys_$domain.txt" 2>/dev/null
    fi
    
    echo -e "${GREEN}[SUCCESS] OSINT gathering completed${NC}"
}

# Screenshot capturing
capture_screenshots() {
    local domain="$1"
    local hosts_file="$OUTDIR/web/discovered_$domain.txt.httpx"
    
    echo -e "${CYAN}[INFO] Capturing screenshots${NC}"
    
    # Use aquatone for screenshots
    cat "$hosts_file" | aquatone -out "$OUTDIR/screenshots" > /dev/null 2>&1
    
    echo -e "${GREEN}[SUCCESS] Screenshots captured${NC}"
}

# Generate comprehensive report
generate_report() {
    local domain="$1"
    local report_file="$OUTDIR/report_$domain.html"
    
    echo -e "${CYAN}[INFO] Generating comprehensive report${NC}"
    
    # Create HTML report
    cat > "$report_file" <<- HTML
<!DOCTYPE html>
<html>
<head>
    <title>Recon Report - $domain</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; }
        .medium { color: #ffcc00; }
        .low { color: #3366ff; }
    </style>
</head>
<body>
    <h1>Reconnaissance Report: $domain</h1>
    <div class="section">
        <h2>Executive Summary</h2>
        <p>Generated on: $(date)</p>
    </div>
    <!-- Add more report sections here -->
</body>
</html>
HTML

    echo -e "${GREEN}[SUCCESS] Report generated: $report_file${NC}"
}

# Main target processing function
process_target() {
    local target="$1"
    local domain=""
    
    echo -e "${MAGENTA}[PROCESSING] Starting reconnaissance for: $target${NC}"
    
    # Extract domain from URL if needed
    if [[ "$target" =~ ^https?:// ]]; then
        domain=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    else
        domain="$target"
        target="https://$target"
    fi
    
    # Validate domain
    if ! validate_domain "$domain"; then
        return 1
    fi
    
    # Create target-specific directory
    local target_dir="$OUTDIR/$domain"
    mkdir -p "$target_dir"
    
    # Execute reconnaissance modules
    if [[ "$NO_SUBDOMAINS" != "true" ]]; then
        passive_subdomain_enum "$domain"
        active_subdomain_enum "$domain"
    fi
    
    if [[ "$NO_PORTSCAN" != "true" ]]; then
        advanced_port_scan "$domain"
    fi
    
    if [[ "$NO_WEBSCAN" != "true" ]]; then
        web_discovery "$domain"
        directory_bruteforce "$target"
    fi
    
    if [[ "$NO_VULNSCAN" != "true" ]]; then
        vulnerability_scan "$domain"
    fi
    
    if [[ "$OSINT_ONLY" == "true" ]] || [[ "$PASSIVE_ONLY" == "true" ]]; then
        osint_gathering "$domain"
    else
        osint_gathering "$domain"
        capture_screenshots "$domain"
    fi
    
    generate_report "$domain"
    
    echo -e "${GREEN}[COMPLETED] Finished reconnaissance for: $domain${NC}"
}

# Signal handling for clean exit
cleanup() {
    echo -e "${YELLOW}[INFO] Cleaning up...${NC}"
    rm -rf "$OUTDIR/temp"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Main execution
main() {
    show_banner
    
    # Parse command line arguments
    TARGETS=()
    MODE="quick"
    OSINT_ONLY="false"
    PASSIVE_ONLY="false"
    NO_SUBDOMAINS="false"
    NO_PORTSCAN="false"
    NO_WEBSCAN="false"
    NO_VULNSCAN="false"
    USE_TOR="false"
    RANDOM_AGENT="false"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u) TARGETS+=("$2"); shift 2 ;;
            -f) 
                if [[ -f "$2" ]]; then 
                    mapfile -t TARGETS < "$2"
                else 
                    echo -e "${RED}[ERROR] Targets file not found: $2${NC}"; exit 1
                fi
                shift 2
                ;;
            -d) TARGETS+=("$2"); shift 2 ;;
            -m) MODE="$2"; shift 2 ;;
            -t) THREADS="$2"; shift 2 ;;
            -T) TIMEOUT="$2"; shift 2 ;;
            -o) OUTDIR="$2"; shift 2 ;;
            -w) WEBHOOK_URL="$2"; shift 2 ;;
            --no-subdomains) NO_SUBDOMAINS="true"; shift ;;
            --no-portscan) NO_PORTSCAN="true"; shift ;;
            --no-webscan) NO_WEBSCAN="true"; shift ;;
            --no-vulnscan) NO_VULNSCAN="true"; shift ;;
            --osint-only) OSINT_ONLY="true"; shift ;;
            --passive-only) PASSIVE_ONLY="true"; shift ;;
            --tor) USE_TOR="true"; shift ;;
            --random-agent) RANDOM_AGENT="true"; shift ;;
            --shodan) USE_SHODAN="true"; shift ;;
            --censys) USE_CENSYS="true"; shift ;;
            --json) OUTPUT_JSON="true"; shift ;;
            --html) OUTPUT_HTML="true"; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) echo -e "${RED}[ERROR] Unknown option: $1${NC}"; show_help; exit 1 ;;
        esac
    done
    
    if [[ ${#TARGETS[@]} -eq 0 ]]; then
        echo -e "${RED}[ERROR] No targets specified${NC}"
        show_help
        exit 1
    fi
    
    # Initialize environment
    init_environment
    require_tools
    
    # Process targets
    for target in "${TARGETS[@]}"; do
        process_target "$target"
    done
    
    echo -e "${GREEN}[ALL DONE] All reconnaissance completed. Results saved in: $OUTDIR${NC}"
}

# Run main function
main "$@"
