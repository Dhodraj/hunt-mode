#!/bin/bash
# 7-Question Validation Gate
# Run this BEFORE writing any report. ONE wrong answer = KILL the finding.
#
# Usage: ./tools/validate.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "======================================"
echo "  7-Question Validation Gate"
echo "======================================"
echo ""
echo "Answer each question Y/N. ONE 'N' = KILL the finding."
echo ""

PASS=true

questions=(
  "Q1: Can you demonstrate this step-by-step RIGHT NOW with an exact HTTP request?"
  "Q2: Is the impact accepted by this program? (check scope page)"
  "Q3: Is the vulnerable asset explicitly listed in scope?"
  "Q4: Does it work WITHOUT admin/privileged access? (admin bugs = usually informative)"
  "Q5: Have you checked Hacktivity + changelog and confirmed this is NOT already known?"
  "Q6: Can you prove REAL impact? (actual data leaked, not just 200 OK or theory)"
  "Q7: Is this NOT on the never-submit list? (missing headers, introspection alone, self-XSS, DNS-only SSRF)"
)

for q in "${questions[@]}"; do
  echo -e "${YELLOW}$q${NC}"
  read -p "  [Y/N]: " answer
  if [[ "$answer" != "Y" && "$answer" != "y" ]]; then
    echo -e "  ${RED}FAIL — KILL this finding. Move on.${NC}"
    PASS=false
    break
  else
    echo -e "  ${GREEN}PASS${NC}"
  fi
  echo ""
done

echo ""
echo "======================================"
if $PASS; then
  echo -e "${GREEN}ALL 7 QUESTIONS PASSED${NC}"
  echo ""
  echo "Now run the 4 Gates:"
  echo "  Gate 0: [ ] Confirmed with real HTTP requests"
  echo "          [ ] In scope (checked program page)"
  echo "          [ ] Reproducible from scratch"
  echo "          [ ] Evidence captured (screenshots/curl output)"
  echo ""
  echo "  Gate 1: [ ] Can answer 'What does attacker walk away with?'"
  echo "          [ ] More than 'sees non-sensitive data'"
  echo "          [ ] Real victim exists"
  echo ""
  echo "  Gate 2: [ ] Searched Hacktivity for endpoint + bug class"
  echo "          [ ] Searched GitHub issues"
  echo "          [ ] Not in changelog as known fix"
  echo ""
  echo "  Gate 3: [ ] Title: [Class] in [Endpoint] allows [actor] to [impact]"
  echo "          [ ] Steps have exact HTTP request"
  echo "          [ ] Under 600 words"
  echo ""
  echo -e "${GREEN}If all gates pass → proceed to write report${NC}"
else
  echo -e "${RED}FINDING KILLED — Do not write a report.${NC}"
  echo "Move on to the next target/endpoint."
fi
