####################
# Main entry point #
####################
show_help(){
  cat <<-HELP
Usage: $0 -u <domain|url> | -f <targets_file>
Options:
  -u <url>        Single target (domain or URL)
  -f <file>       File with targets (one per line)
  -w <webhook>    Optional: webhook URL to POST JSON reports
  -t <threads>    Concurrency for tools that accept it (default $THREADS)
  -h              Show this help
HELP
}

if [[ $# -eq 0 ]]; then
  show_help
  exit 1
fi

TARGETS=()
while getopts "u:f:w:t:h" opt; do
  case $opt in
    u) TARGETS+=("$OPTARG") ;;
    f) if [[ -f "$OPTARG" ]]; then mapfile -t TARGETS < "$OPTARG"; else echo "Targets file not found: $OPTARG"; exit 1; fi ;;
    w) WEBHOOK_URL="$OPTARG" ;;
    t) THREADS="$OPTARG" ;;
    h) show_help; exit 0 ;;
    *) show_help; exit 1 ;;
  esac
done

require_tools

# Process each target sequentially (could be parallelized carefully)
for t in "${TARGETS[@]}"; do
  process_target "$t"
done

echo "All done. Reports saved under: $OUTDIR"
