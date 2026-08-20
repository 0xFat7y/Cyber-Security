# W!ldC4rd — CTF Team Reconnaissance Automation Tool

> **For authorized security testing and bug bounty reconnaissance only.**
> Always obtain written permission before testing any target.

---

## Overview

W!ldC4rd is a modular, professional-grade Python 3 reconnaissance framework built for CTF teams and bug bounty hunters. It automates the full passive/active recon workflow — from subdomain enumeration to JavaScript secret extraction. It is **not** a vulnerability scanner — it focuses entirely on information gathering, endpoint discovery, and JavaScript analysis.

---

## Workflow

```
Target Domain
│
├── 1.  Workspace creation + logging
├── 2.  Browser: Censys, SecurityTrails
├── 3.  Google Dorking (9 queries opened in browser)
│         site:*.target.com
│         site:*.*.target.com
│         site:*.*.*.target.com
│         site:*.target.*  (TLD wildcard)
│         site:target.com -www
│         inurl:target.com
│         intitle:"Index of" site:*.target.com
│         "target.com" filetype:pdf
│         "target.com" ext:env OR ext:log OR ext:conf
│         → google_dorks.txt (all query URLs saved)
│
├── 4.  WHOIS lookup
├── 5.  Subdomain enumeration
│         subfinder (2-pass: all sources + recursive -dL)
│         amass (passive, 30min timeout)
│         assetfinder
│         crt.sh (3 retries with backoff)
│
├── 6.  httpx — live host probing + metadata
│         → subdomains_info.txt (200 / 3xx / 403)
│         → live_subdomains.txt (200 only)
│
├── 7.  EyeWitness — screenshots + HTML report
│         Input: live_subdomains.txt (200 hosts only)
│         → eyewitness/report.html
│         → eyewitness/*.png  (per-host screenshots)
│
├── 8.  Historical URL collection
│         waybackurls (primary, 2h timeout)
│         gau (fallback if waybackurls fails, 2h timeout)
│         → uro deduplication
│         → httpx probing → active_endpoints.txt
│
├── 9.  Parameter extraction → params.txt
│         Format: https://target.com/path?param=
│         (one line per parameter, value blanked for fuzzing)
│
├── 10. GF patterns → gf/{xss,sqli,ssrf,lfi,rce,...}.txt
│         fallback to live_subdomains.txt if no active endpoints
│
├── 11. Katana crawl (all live hosts, depth 5)
│         + JS collection from wayback URLs
│         + JS collection from active endpoints
│
├── 12. JS Analysis (concurrent, 10 workers)
│         xnLinkFinder → js_urls.txt + endpoints.txt
│         Inline regex  → secrets.json
│
└── 13. Recon Summary
```

---

## Output Structure

```
<domain>/
├── recon.log                    # Full timestamped log
├── whois.txt                    # WHOIS data
├── google_dorks.txt             # All 9 dork query URLs (for manual review)
├── subdomains.txt               # All unique subdomains (merged + sorted)
├── subfinder.txt                # subfinder pass-1 output
├── subfinder_recursive.txt      # subfinder pass-2 output
├── subfinder_input.txt          # Input list for pass-2
├── amass.txt                    # amass output
├── crtsh.txt                    # crt.sh output
├── katana_targets.txt           # Live hosts fed to katana
├── subdomains_info.txt          # httpx: 200/3xx/403 with metadata
├── live_subdomains.txt          # httpx: HTTP 200 hosts only
├── wayback_raw.txt              # Raw historical URLs
├── gau_deduped.txt              # After uro deduplication
├── active_endpoints.txt         # Reachable endpoints (probed via httpx)
├── active_raw.json              # Raw httpx JSON for endpoints
├── params.txt                   # Parameters as full fuzz-ready URLs
│                                #   e.g. https://target.com/path?id=
├── katana.txt                   # Katana crawl output
├── eyewitness/
│   ├── report.html              # Self-contained HTML report (auto-opened)
│   └── *.png                    # Per-host screenshots
├── js/
│   ├── js_files.txt             # All discovered JS file URLs
│   ├── js_urls.txt              # URLs extracted from JS
│   ├── endpoints.txt            # API endpoints found in JS
│   └── secrets.json             # Classified secrets (structured JSON)
└── gf/
    ├── xss.txt
    ├── sqli.txt
    ├── ssrf.txt
    ├── redirect.txt
    ├── lfi.txt
    ├── rce.txt
    ├── upload.txt
    ├── idor.txt
    ├── debug.txt
    └── aws-keys.txt
```

---

## Secret Categories Detected (Inline Regex)

| Category | Pattern |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | Inline `aws_secret` patterns |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` |
| Firebase Key | FCM server key format |
| GitHub Token | `ghp_` / `github_pat_` |
| JWT Token | `eyJ...` triple-segment |
| Bearer Token | Authorization header patterns |
| Slack Token | `xox[baprs]-...` |
| Stripe Live Key | `sk_live_...` |
| Stripe Public Key | `pk_live_...` |
| Twilio SID | `AC[a-z0-9]{32}` |
| Private Key | PEM header detection |
| Mailgun API Key | `key-[0-9a-zA-Z]{32}` |
| SendGrid | `SG....` format |
| Heroku API Key | UUID format |
| Shopify Token | `shpss_` / `shpat_` |

---

## Installation

### 1. Install Python dependencies

```bash
pip3 install -r requirements.txt --break-system-packages
# or
sudo apt install python3-requests python3-urllib3
```

### 2. Install all external tools (automated)

```bash
bash install_tools.sh
```

This script installs:
- **System:** `whois`, `git`, `python3`
- **Go tools:** `subfinder`, `amass`, `assetfinder`, `httpx`, `waybackurls`, `gau`, `uro`, `gf`, `katana`
- **Python tools:** `xnLinkFinder`
- **GF patterns:** 1ndianl33t's pattern collection

### 3. Install EyeWitness (screenshots)

**Option A — apt (Kali / Debian recommended):**
```bash
sudo apt install eyewitness
```

**Option B — from source:**
```bash
git clone https://github.com/RedSiege/EyeWitness.git ~/tools/EyeWitness
cd ~/tools/EyeWitness/Python3
pip3 install -r requirements.txt --break-system-packages
sudo ln -sf ~/tools/EyeWitness/Python3/EyeWitness.py /usr/local/bin/eyewitness
sudo chmod +x ~/tools/EyeWitness/Python3/EyeWitness.py
```

EyeWitness is **optional** — if not found, the screenshot stage is automatically skipped and all other stages continue normally.

### 4. Manual Go tool installation

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/gf@latest
go install github.com/s0md3v/uro@latest
go install github.com/owasp-amass/amass/v4/...@master
```

---

## Usage

```bash
python3 wildcard.py
```

Enter the target domain when prompted:

```
  [?] Enter the target domain (e.g. example.com): bugcrowd.com
```

### Interrupt safely

Press `Ctrl+C` at any time — partial results are preserved in the project directory.

---

## Tool Availability Handling

W!ldC4rd checks for every external tool before execution. If a tool is missing:

- A **warning** is printed in yellow
- That **stage is skipped**
- All other stages **continue normally**

---

## Historical URL Collection Logic

```
waybackurls available?
  ✔ YES → run waybackurls (2h timeout)
           ✔ success → done, skip gau
           ✘ fail/no output → fallback to gau (2h timeout)
  ✘ NO  → run gau directly (2h timeout)
```

---

## Google Dorking

W!ldC4rd automatically opens 9 targeted Google dork queries in your browser immediately after the OSINT browser tabs (Stage 3). This surfaces assets that passive enumeration tools often miss — deeply nested subdomains, exposed files, and open directories indexed by Google.

| Dork | Purpose |
|---|---|
| `site:*.target.com` | First-level subdomains |
| `site:*.*.target.com` | Second-level subdomains |
| `site:*.*.*.target.com` | Third-level (deep) subdomains |
| `site:*.target.*` | TLD wildcard — alternate TLDs |
| `site:target.com -www` | Root domain assets |
| `inurl:target.com` | Pages referencing the domain in URL |
| `intitle:"Index of" site:*.target.com` | Open directory listings |
| `"target.com" filetype:pdf` | Indexed PDF documents |
| `"target.com" ext:env OR ext:log OR ext:conf` | Exposed config/log files |

All queries and their full Google URLs are saved to `google_dorks.txt` for later reference or sharing with teammates.

---

## EyeWitness Screenshots

After `httpx` identifies live hosts (Stage 7), W!ldC4rd runs EyeWitness to take screenshots of every HTTP 200 host and produces a self-contained HTML report at `eyewitness/report.html`. The report is automatically opened in your browser on completion.

The report is especially useful for:
- Quickly triaging large scopes visually (login pages, admin panels, default configs)
- Spotting interesting or forgotten subdomains without visiting each URL manually
- Sharing recon results with the team in a readable format

EyeWitness configuration used: `--web`, 10 threads, 15s per-host timeout, tries both HTTP and HTTPS (`--cycle both`), auto-resolves DNS.

If EyeWitness is not installed, this stage is silently skipped — see [Installation](#3-install-eyewitness-screenshots).

---

## Parameter Extraction Format

`params.txt` stores parameters as **fuzz-ready URLs**, one per line, with the value deliberately left blank:

```
https://target.com/api/users?id=
https://target.com/search?q=
https://target.com/search?page=
https://app.target.com/items?category=&sort=
```

Each parameter gets its own line even if multiple parameters appear in the same original URL. This format lets you pipe `params.txt` directly into fuzzing tools without any preprocessing:

```bash
# ffuf
ffuf -w wordlist.txt -u FUZZ -ic -c < params.txt

# with a custom payload list
while read url; do
    ffuf -w payloads.txt -u "${url}FUZZ"
done < params.txt
```

---

## Requirements

- Python 3.9+
- Linux / macOS (WSL supported on Windows)
- Go 1.21+ (for Go-based tools)
- Internet access for crt.sh queries and tool fetching

---

## Legal Notice

This tool is provided for **authorized penetration testing and bug bounty research only**.
Unauthorized use against systems you do not own or have explicit written permission to test is **illegal**.
The authors assume no liability for misuse.
