# Recon Toolkit - Installation & Usage

## Essential Tools

### 1. Burp Suite Community Edition (MUST HAVE)
**What:** Intercepting proxy - see and modify all HTTP traffic
**Install:** Download from https://portswigger.net/burp/communitydownload
**Quick start:**
```
1. Open Burp Suite → Proxy tab → Intercept is on
2. Set browser proxy to 127.0.0.1:8080
3. Browse target site - all requests appear in Burp
4. Use Repeater (Ctrl+R) to modify and replay requests
```

### 2. subfinder - Subdomain Enumeration
**What:** Finds subdomains of a target domain
**Install:**
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```
**Usage:**
```bash
subfinder -d target.com -o subdomains.txt
```

### 3. httpx - HTTP Probing
**What:** Checks which subdomains are alive and gets status codes
**Install:**
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```
**Usage:**
```bash
cat subdomains.txt | httpx -status-code -title -tech-detect -o alive.txt
```

### 4. nuclei - Vulnerability Scanner
**What:** Automated scanning with community templates
**Install:**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```
**Usage:**
```bash
nuclei -l alive.txt -t cves/ -t vulnerabilities/ -o nuclei-results.txt
```

### 5. ffuf - Web Fuzzer
**What:** Discovers hidden directories, files, parameters
**Install:**
```bash
go install github.com/ffuf/ffuf/v2@latest
```
**Usage:**
```bash
# Directory brute forcing
ffuf -u https://target.com/FUZZ -w wordlists/common.txt -mc 200,301,302,403

# Parameter fuzzing
ffuf -u https://target.com/api/endpoint?FUZZ=value -w wordlists/params.txt
```

### 6. gau (Get All URLs)
**What:** Fetches known URLs from Wayback Machine, Common Crawl, etc.
**Install:**
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```
**Usage:**
```bash
echo target.com | gau --threads 5 -o urls.txt
```

### 7. waybackurls
**What:** Fetches URLs from Wayback Machine
**Install:**
```bash
go install github.com/tomnomnom/waybackurls@latest
```
**Usage:**
```bash
echo target.com | waybackurls > wayback-urls.txt
```

## Optional but Useful

| Tool | Purpose | Install |
|------|---------|---------|
| `amass` | Advanced subdomain enum | `go install github.com/owasp-amass/amass/v4/...@master` |
| `nmap` | Port scanning | `sudo apt install nmap` |
| `sqlmap` | SQL injection testing | `sudo apt install sqlmap` |
| `dirsearch` | Directory brute forcing | `pip install dirsearch` |
| `paramspider` | Parameter discovery | `pip install paramspider` |

## Tips
- Always check program scope before scanning - some programs ban automated scanning
- Start with passive recon (subfinder, gau) before active scanning (ffuf, nuclei)
- Use `-rate-limit` flags to avoid getting IP banned
- Save all output to files for later reference
