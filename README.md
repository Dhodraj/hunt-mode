# HuntMode

**Security research and bug bounty hunting toolkit.**

A structured workspace for finding security vulnerabilities in public bug bounty programs. Built around a methodology that emphasizes source code auditing, local testing, and rigorous validation before submission.

> **Disclaimer:** This toolkit is intended solely for authorized security testing on programs with explicit bug bounty or vulnerability disclosure policies. Never test systems without written permission. All tools and scripts are designed for use against local test instances (GDK, Docker, etc.) — not production systems.

---

## Features

- **Structured target workspace** — Templates for scope, recon, and findings per target
- **Recon automation** — Pipeline script for subdomain enumeration, HTTP probing, and URL discovery
- **PoC development scripts** — Proof-of-concept templates for common vulnerability classes (SSRF, validation bypass, auth bypass, XSS)
- **Playwright-based XSS verification** — Automated browser testing with video evidence capture
- **7-Question Validation Gate** — Interactive checklist to prevent low-quality report submissions
- **Dedup checker** — Search HackerOne Hacktivity before submitting to avoid duplicates
- **HackerOne API tools** — Search disclosed reports, get program stats and policies
- **Scope checker** — Deterministic URL validation against program scope (anchored domain matching, not naive glob)
- **Hunt memory system** — JSONL-backed journal and pattern database for cross-target learning
- **Report templates** — HackerOne/Bugcrowd report format with proven structure

## Directory Structure

```
HuntMode/
├── README.md                 # This file
├── learning/                 # Roadmap and study notes
│   └── roadmap.md            # Phased learning plan
├── recon/                    # Reconnaissance tools and data
│   ├── scripts/              # recon-runner.sh (automated pipeline)
│   ├── wordlists/            # Directory/parameter/API endpoint lists
│   └── tools.md              # Tool installation and usage guide
├── scripts/                  # PoC scripts and utilities
│   ├── new-target.sh         # Create new target workspace from template
│   ├── poc-*.py              # Proof-of-concept exploit scripts
│   └── verify-*.py           # Verification/testing scripts
├── tools/                    # Reusable hunting tools
│   ├── dedup_check.py        # HackerOne Hacktivity search
│   ├── hackerone_search.py   # HackerOne GraphQL API client
│   ├── scope_checker.py      # Deterministic scope validation
│   ├── validate.sh           # 7-Question Validation Gate
│   └── memory/               # Hunt memory system
│       ├── hunt_journal.py   # Append-only JSONL journal
│       ├── pattern_db.py     # Successful technique database
│       └── schemas.py        # Entry validation schemas
├── tracker.md                # Master bounty tracker
└── .gitignore                # Excludes targets, reports, secrets
```

## Methodology

Based on the [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty) framework, adapted with lessons learned.

### Core Principle

> "Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions — and does it cause real harm?"
> If NO — STOP. Do not write. Move on.

### Workflow

1. **Target selection** — Pick a program with source code access and local testing capability
2. **Recon** — Run `recon-runner.sh`, review scope, identify attack surface
3. **Source code audit** — Read the code, trace input to dangerous sinks
4. **Local PoC** — Build and test exploits against local instances (GDK, Docker, etc.)
5. **Validation gate** — Run `tools/validate.sh` (7-question checklist)
6. **Dedup check** — Run `tools/dedup_check.py` to search for existing reports
7. **Report** — Write using the report template, include source code references and working PoC
8. **Submit** — Only after human review

### Priority Vulnerability Classes

**Hunt these (lower competition):**
- Race conditions, business logic flaws
- Cache poisoning, CI/CD pipeline attacks
- OAuth/OIDC chains, import/export features

**Avoid unless target-specific (high competition):**
- Basic XSS, basic SSRF, open redirect alone, missing headers

### Time Rules

- **5 minutes** — target shows nothing? Move on
- **20 minutes** — no progress on endpoint? Rotate
- **1 hour** — stuck on one target? Switch context

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Community | Intercepting proxy |
| Playwright (Python) | Browser automation, XSS testing, video evidence |
| subfinder | Subdomain enumeration |
| httpx | HTTP probing and tech detection |
| nuclei | Template-based vulnerability scanning |
| ffuf | Web fuzzing (directories, parameters) |
| gau / waybackurls | Historical URL discovery |
| GitLab GDK | Local GitLab instance for safe testing |

## Getting Started

### 1. Create a new target workspace

```bash
./scripts/new-target.sh <target-name>
```

### 2. Fill in scope

Edit `targets/<target-name>/scope.md` with program details from the bug bounty platform.

### 3. Run recon

```bash
./recon/scripts/recon-runner.sh <domain>
```

### 4. Start hunting

Use source code audit + local testing. Build PoCs in `scripts/`. Record findings in `targets/<target-name>/findings.md`.

### 5. Validate before reporting

```bash
./tools/validate.sh
python3 tools/dedup_check.py "<target> <vuln-type>"
```

## Report Writing

**Title formula:** `[Bug Class] in [Endpoint] allows [actor] to [impact]`

**Structure:**
1. Summary (1-2 sentences)
2. Affected versions / components
3. Root cause with source code references
4. Step-by-step reproduction with HTTP requests
5. Working PoC
6. Impact assessment
7. Suggested fix

**Rules:**
- Never say "could potentially" or "may allow" — state facts
- Impact first — what does the attacker walk away with?
- Under 600 words — triagers skim
- Copy-pasteable HTTP requests

## License

This project is provided as-is for educational and authorized security research purposes only. Use responsibly.
