# Bug Bounty Learning Roadmap

## Phase 1: Foundations (Week 1)

- [ ] Set up Burp Suite Community Edition
- [ ] Learn to intercept and modify HTTP requests with Burp Proxy
- [ ] Complete PortSwigger Academy: "How websites work" section
- [ ] Read OWASP Top 10 (overview, not deep dive)
- [ ] Read 10 disclosed reports on HackerOne Hacktivity (filter by "disclosed", sort by upvotes)

### Key Concepts to Understand
- HTTP request/response cycle
- Cookies, sessions, tokens (JWT)
- Same-origin policy and CORS
- Authentication vs Authorization

## Phase 2: First Vulnerability Classes (Week 2)

### IDOR / Broken Access Control (START HERE - highest ROI)
- [ ] PortSwigger Academy: Access Control labs (all free labs)
- [ ] Practice: change user IDs in API requests, check if you can access other users' data
- [ ] Read 5 disclosed IDOR reports on HackerOne

### XSS (Cross-Site Scripting)
- [ ] PortSwigger Academy: XSS labs (reflected + stored)
- [ ] Understand: reflected vs stored vs DOM-based
- [ ] Practice basic payloads: `<script>alert(1)</script>`, event handlers
- [ ] Read 5 disclosed XSS reports on HackerOne

### SSRF (Server-Side Request Forgery)
- [ ] PortSwigger Academy: SSRF labs
- [ ] Understand: internal network access, cloud metadata endpoints
- [ ] Read 5 disclosed SSRF reports on HackerOne

## Phase 3: Start Hunting (Week 3+)

- [ ] Sign up on HackerOne
- [ ] Pick 2-3 beginner-friendly programs (wide scope, VDP or low bounty)
- [ ] Run recon on first target
- [ ] Spend focused time (2-4 hours) manually testing one target
- [ ] Submit first report (even if low severity)

## Phase 4: Level Up (Month 2+)

- [ ] Learn: SQL Injection, Authentication bypasses, Business logic flaws
- [ ] Start targeting paid bounty programs
- [ ] Build custom automation for repetitive tasks
- [ ] Study disclosed reports weekly (at least 5/week)
- [ ] Join bug bounty communities (Discord, Twitter/X)

## Resources

### Free & Essential
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security (best free resource)
- **HackerOne Hacktivity**: https://hackerone.com/hacktivity (real disclosed reports)
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

### YouTube Channels
- NahamSec (bug bounty focused)
- STOK (methodology & motivation)
- John Hammond (CTFs & security)
- LiveOverflow (deep technical content)

### Books (when ready)
- "The Web Application Hacker's Handbook" (classic)
- "Bug Bounty Bootcamp" by Vickie Li (beginner friendly)
