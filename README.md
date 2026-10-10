# hunt-mode

A workspace and a set of scripts for bug bounty work. It keeps each target's scope, recon and findings in order, and it leans on reading source code rather than firing scanners.

Built in 2026.

> Only test programs that have a public bug bounty or disclosure policy, and stay inside their scope. The scripts here assume you have that permission.

## How I work with it

1. `scripts/new-target.sh` makes a folder for a target from a template: scope, recon notes, findings.
2. `recon/scripts/recon-runner.sh` runs the recon chain: subfinder, httpx, gau and waybackurls for URLs, then nuclei.
3. I read the source where I can, and trace user input to where it lands.
4. I build a proof of concept against a local instance, such as a GitLab GDK or a Docker image, not against the live site.
5. `tools/validate.sh` asks seven questions before I write anything up, so weak findings do not become reports.
6. `tools/dedup_check.py` searches HackerOne Hacktivity for the same bug before I submit.

## What is in here

- `tools/scope_checker.py` decides if a URL is in scope. It matches the domain suffix in an anchored way, so `evil-gitlab.com` does not pass as `gitlab.com`.
- `tools/hackerone_search.py` searches disclosed reports and reads program stats and policies.
- `tools/memory/` keeps a JSONL journal and a pattern database, so what I learn on one target carries to the next.
- `recon/wordlists/` holds the directory, parameter and endpoint lists the recon script uses.
- `learning/roadmap.md` is my study plan.

The methodology is adapted from [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty).

## Run a tool

The Python tools need Python 3. The recon script needs subfinder, httpx, gau, waybackurls and nuclei on your PATH. For example:

```bash
python tools/scope_checker.py
bash recon/scripts/recon-runner.sh
```
