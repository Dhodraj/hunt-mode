#!/bin/bash
# Automated recon pipeline for a target domain
# Usage: ./recon-runner.sh <domain> [output-dir]

if [ -z "$1" ]; then
    echo "Usage: ./recon-runner.sh <domain> [output-dir]"
    echo "Example: ./recon-runner.sh example.com"
    echo "Example: ./recon-runner.sh example.com ../../targets/example/recon-output"
    exit 1
fi

DOMAIN="$1"
OUTPUT_DIR="${2:-./output/$DOMAIN}"
mkdir -p "$OUTPUT_DIR"

echo "========================================="
echo " Recon Pipeline: $DOMAIN"
echo " Output: $OUTPUT_DIR"
echo "========================================="

# Step 1: Subdomain Enumeration
echo ""
echo "[1/5] Subdomain enumeration (subfinder)..."
if command -v subfinder &> /dev/null; then
    subfinder -d "$DOMAIN" -silent -o "$OUTPUT_DIR/subdomains.txt"
    SUB_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains.txt" 2>/dev/null || echo 0)
    echo "  Found $SUB_COUNT subdomains"
else
    echo "  SKIP: subfinder not installed (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)"
fi

# Step 2: HTTP Probing
echo ""
echo "[2/5] Probing live hosts (httpx)..."
if command -v httpx &> /dev/null && [ -f "$OUTPUT_DIR/subdomains.txt" ]; then
    cat "$OUTPUT_DIR/subdomains.txt" | httpx -silent -status-code -title -tech-detect -o "$OUTPUT_DIR/alive.txt"
    ALIVE_COUNT=$(wc -l < "$OUTPUT_DIR/alive.txt" 2>/dev/null || echo 0)
    echo "  Found $ALIVE_COUNT live hosts"
else
    echo "  SKIP: httpx not installed or no subdomains found"
fi

# Step 3: URL Discovery
echo ""
echo "[3/5] URL discovery (gau)..."
if command -v gau &> /dev/null; then
    echo "$DOMAIN" | gau --threads 5 --o "$OUTPUT_DIR/urls-gau.txt" 2>/dev/null
    URL_COUNT=$(wc -l < "$OUTPUT_DIR/urls-gau.txt" 2>/dev/null || echo 0)
    echo "  Found $URL_COUNT historical URLs"
else
    echo "  SKIP: gau not installed (go install github.com/lc/gau/v2/cmd/gau@latest)"
fi

# Step 4: Wayback URLs
echo ""
echo "[4/5] Wayback Machine URLs..."
if command -v waybackurls &> /dev/null; then
    echo "$DOMAIN" | waybackurls > "$OUTPUT_DIR/urls-wayback.txt" 2>/dev/null
    WB_COUNT=$(wc -l < "$OUTPUT_DIR/urls-wayback.txt" 2>/dev/null || echo 0)
    echo "  Found $WB_COUNT wayback URLs"
else
    echo "  SKIP: waybackurls not installed (go install github.com/tomnomnom/waybackurls@latest)"
fi

# Step 5: Merge and deduplicate URLs
echo ""
echo "[5/5] Merging and deduplicating..."
cat "$OUTPUT_DIR"/urls-*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/all-urls.txt"
TOTAL=$(wc -l < "$OUTPUT_DIR/all-urls.txt" 2>/dev/null || echo 0)
echo "  Total unique URLs: $TOTAL"

# Summary
echo ""
echo "========================================="
echo " Recon Complete!"
echo "========================================="
echo " Subdomains:  $OUTPUT_DIR/subdomains.txt"
echo " Live hosts:  $OUTPUT_DIR/alive.txt"
echo " All URLs:    $OUTPUT_DIR/all-urls.txt"
echo ""
echo "Next steps:"
echo "  1. Review alive.txt for interesting hosts"
echo "  2. Look for API endpoints in all-urls.txt"
echo "  3. Run nuclei: nuclei -l alive.txt -o nuclei-results.txt"
echo "  4. Manual testing with Burp Suite on interesting endpoints"
