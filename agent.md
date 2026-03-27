# HuntMode — Agent Configuration

## Purpose

AI-assisted bug bounty hunting workspace. The agent assists with every phase: recon, testing, source code auditing, PoC development, and report writing.

## Autonomy Rules

### AUTONOMOUS (do without asking):
- Read any file in this workspace or target source code
- Search codebases (grep, glob, git log, git blame)
- Install tools via apt, pip, npm, go install
- Create files in this workspace (scripts, reports, notes, templates)
- Run scripts against LOCAL test instances only
- Source code audit — read, search, trace code paths
- Web searches for disclosed reports, CVEs, tool documentation
- Git operations in this workspace: status, diff, log, add, commit
- Draft reports ready for review
- Run parallel agents for independent tasks

### PROMPT USER FIRST:
- Modify/delete existing non-generated files
- Submit reports to bug bounty platforms
- Push to any remote git repository
- Test on production systems
- Delete targets, findings, or evidence
- Run destructive commands

### NEVER DO:
- Store passwords, API keys, or secrets in tracked files
- Test vulnerabilities on production without explicit permission
- Submit reports without user review
- Run automated scanners against production systems

## Hunting Methodology

### The Only Question That Matters
> "Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions — and does it cause real harm?"
> If NO — STOP. Move on.

### 7-Question Validation Gate (before every report)
1. Can I demonstrate this step-by-step RIGHT NOW?
2. Is the impact accepted by this program?
3. Is the vulnerable asset in scope?
4. Does it need admin/privileged access an attacker can't get?
5. Is this known or documented?
6. Can I prove impact beyond "technically possible"?
7. Is this on the never-submit list?

**ONE wrong answer = KILL the finding.**

### A→B Chain Hunting
| Found A | Check B | Check C |
|---|---|---|
| IDOR read | PUT/DELETE same endpoint | Sibling endpoints |
| SSRF DNS callback | Cloud metadata (169.254.x.x) | Internal services |
| XSS stored | Admin views it? (privesc) | Session hijack |
| Open redirect | OAuth redirect_uri | Auth code theft |
| Auth bypass on 1 endpoint | Every sibling in same controller | Old API version |

### Dedup Check (before submitting)
1. Search platform Hacktivity for endpoint + bug class
2. Search GitHub issues for the vulnerability pattern
3. Read 5 most recent disclosed reports for the program
4. Check changelog for known fixes
5. Search CVE databases

### Report Writing Rules
- **Title formula:** `[Bug Class] in [Endpoint] allows [actor] to [impact]`
- **Impact first:** sentence 1 = what attacker gets
- **Quantify:** how many users, what data type
- **Keep under 600 words**
- **Copy-pasteable HTTP requests** in Steps to Reproduce

### Kill Signals (move on immediately)
- 403 no matter what you try
- 20+ payload variations, identical response
- Finding needs 5+ simultaneous preconditions
- 30+ min on same endpoint with no progress
- Dead/unreachable code with a bug in it

### Time Rules
- **5-minute rule:** no signal after 5 min? Move on
- **20-minute rotation:** not progressing? Rotate target
- **1-hour rule:** stuck for an hour? Switch context entirely

### Priority Bug Classes
**Low competition (hunt these):** race conditions, business logic, cache poisoning, CI/CD pipeline attacks, OAuth/OIDC chains, import/export features
**High competition (avoid):** basic XSS, basic SSRF, open redirect alone, missing headers

## Workspace Structure

```
bug-bounty/
├── CLAUDE.md               # Private config (gitignored)
├── agent.md                # This file (public methodology)
├── README.md               # Project overview
├── learning/               # Roadmap, notes
├── recon/                  # Scripts, wordlists, tool guides
├── targets/                # Per-target workspace (gitignored)
├── reports/                # Report drafts (gitignored)
├── scripts/                # Utility scripts
├── tools/                  # Custom tooling
└── tracker.md              # Master bounty tracker
```
