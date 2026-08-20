#!/usr/bin/env python3
"""
W!ldC4rd - CTF Team Reconnaissance Automation Tool
For authorized security testing and bug bounty reconnaissance only.
"""

import sys
import os
import re
import json
import time
import shutil
import logging
import webbrowser
import subprocess
import threading
import concurrent.futures
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────
#  ANSI Colors & Formatting
# ─────────────────────────────────────────────
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"

def c(text: str, color: str, bold: bool = False) -> str:
    prefix = Color.BOLD if bold else ""
    return f"{prefix}{color}{text}{Color.RESET}"

def banner():
    R = Color.RED
    W = Color.WHITE
    G = Color.GREY
    B = Color.BOLD
    RESET = Color.RESET

    title = (
        "\n"
        f"  {B}{W}██╗    ██╗{R}██╗{W}██╗     ██████╗{R} ██████╗{W} ██╗  ██╗██████╗ ██████╗{RESET}\n"
        f"  {B}{W}██║    ██║{R}██║{W}██║     ██╔══██╗{R}██╔════╝{W}██║  ██║██╔══██╗██╔══██╗{RESET}\n"
        f"  {B}{W}██║ █╗ ██║{R}██║{W}██║     ██║  ██║{R}██║     {W}███████║██████╔╝██║  ██║{RESET}\n"
        f"  {B}{W}██║███╗██║{R}██║{W}██║     ██║  ██║{R}██║     {W}╚════██║██╔══██╗██║  ██║{RESET}\n"
        f"  {B}{W}╚███╔███╔╝{R}██║{W}███████╗██████╔╝{R}╚██████╗{W}     ██║██║  ██║██████╔╝{RESET}\n"
        f"  {B}{G} ╚══╝╚══╝ {R}╚═╝{G}╚══════╝╚═════╝  {R}╚═════╝{G}     ╚═╝╚═╝  ╚═╝╚═════╝ {RESET}\n"
        "\n"
    )
    print(title)


# ─────────────────────────────────────────────
#  Spinner
# ─────────────────────────────────────────────
class Spinner:
    FRAMES = ["⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷"]

    def __init__(self, label: str):
        self.label   = label
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        idx = 0
        while not self._stop.is_set():
            frame = self.FRAMES[idx % len(self.FRAMES)]
            sys.stdout.write(f"\r  {c(frame, Color.CYAN)} {self.label} ")
            sys.stdout.flush()
            time.sleep(0.08)
            idx += 1

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()
        sys.stdout.write("\r" + " " * (len(self.label) + 10) + "\r")
        sys.stdout.flush()

# ─────────────────────────────────────────────
#  Logger (dual: file + stderr)
# ─────────────────────────────────────────────
class ReconLogger:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self._file_logger = logging.getLogger("recon_file")
        self._file_logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self._file_logger.addHandler(fh)
        self._file_logger.propagate = False

    def _log(self, level: str, msg: str, color: str):
        ts = datetime.now().strftime("%H:%M:%S")
        icon = {"INFO": "ℹ", "OK": "✔", "WARN": "⚠", "ERROR": "✘", "STEP": "▶", "DEBUG": "·"}[level]
        print(f"  {c(icon, color)} {c(f'[{ts}]', Color.GREY)} {msg}")
        getattr(self._file_logger, {"OK":"info","WARN":"warning","ERROR":"error","STEP":"info","DEBUG":"debug"}.get(level,"info"))(
            f"[{level}] {msg}"
        )

    def info(self, msg):  self._log("INFO",  msg, Color.BLUE)
    def ok(self, msg):    self._log("OK",    msg, Color.GREEN)
    def warn(self, msg):  self._log("WARN",  msg, Color.YELLOW)
    def error(self, msg): self._log("ERROR", msg, Color.RED)
    def step(self, msg):  self._log("STEP",  msg, Color.MAGENTA)
    def debug(self, msg): self._log("DEBUG", msg, Color.GREY)

# ─────────────────────────────────────────────
#  Utility helpers
# ─────────────────────────────────────────────
TOOL_PATHS: dict[str, Optional[str]] = {}

# Alternative command names to try if the primary name is not found
TOOL_ALIASES: dict[str, list[str]] = {
    "LinkFinder":   ["linkfinder", "linkfinder.py", "LinkFinder.py"],
    "SecretFinder": ["secretfinder", "secretfinder.py", "SecretFinder.py"],
    "xnLinkFinder": ["xnLinkFinder", "xnlinkfinder"],
}

def detect_tools(names: list[str], log: ReconLogger) -> dict[str, Optional[str]]:
    log.step("Detecting required external tools …")
    results: dict[str, Optional[str]] = {}
    for name in names:
        # Try primary name first, then aliases
        candidates = [name] + TOOL_ALIASES.get(name, [])
        found_path = None
        found_name = None
        for candidate in candidates:
            path = shutil.which(candidate)
            if path:
                found_path = path
                found_name = candidate
                break
        if found_path:
            results[name] = found_path
            log.ok(f"  {c(name, Color.GREEN, bold=True)} → {found_path}")
        else:
            results[name] = None
            log.warn(f"  {c(name, Color.YELLOW, bold=True)} → not found (stage will be skipped)")
    return results

def run_cmd(
    cmd: list[str],
    log: ReconLogger,
    cwd: Optional[Path] = None,
    timeout: int = 300,
    input_data: Optional[str] = None,
) -> tuple[bool, str, str]:
    """
    Run a subprocess safely.
    Returns (success, stdout, stderr).
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        return result.returncode == 0, result.stdout, result.stderr
    except FileNotFoundError:
        log.error(f"Command not found: {cmd[0]}")
        return False, "", f"FileNotFoundError: {cmd[0]}"
    except subprocess.TimeoutExpired:
        log.warn(f"Command timed out after {timeout}s: {' '.join(cmd[:3])}")
        return False, "", "TimeoutExpired"
    except Exception as exc:
        log.error(f"Unexpected error running {cmd[0]}: {exc}")
        return False, "", str(exc)

def write_lines(path: Path, lines: list[str]):
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

def clean_domain(raw: str) -> str:
    raw = raw.strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.split("/")[0]
    return raw

# ─────────────────────────────────────────────
#  Stage implementations
# ─────────────────────────────────────────────

def stage_create_workspace(domain: str, base_dir: Path, log: ReconLogger) -> Path:
    log.step("Creating project workspace …")
    project = base_dir / domain
    project.mkdir(parents=True, exist_ok=True)
    for sub in ["js", "gf", "secrets", "eyewitness"]:
        (project / sub).mkdir(exist_ok=True)
    log.ok(f"Workspace ready → {project}")
    return project


def stage_open_browser(domain: str, log: ReconLogger):
    log.step("Opening OSINT resources in browser …")
    urls = {
        "Censys":         f"https://search.censys.io/search?resource=hosts&q={domain}",
        "SecurityTrails": f"https://securitytrails.com/domain/{domain}/dns",
    }
    for name, url in urls.items():
        try:
            webbrowser.open_new_tab(url)
            log.ok(f"Opened {name}: {url}")
        except Exception as exc:
            log.warn(f"Could not open {name}: {exc}")


def stage_whois(domain: str, project: Path, log: ReconLogger):
    log.step("Running WHOIS lookup …")
    if not TOOL_PATHS.get("whois"):
        log.warn("whois not found — skipping")
        return
    with Spinner("Running whois …"):
        ok, out, err = run_cmd(["whois", domain], log, timeout=60)
    if ok and out.strip():
        (project / "whois.txt").write_text(out, encoding="utf-8")
        log.ok(f"WHOIS saved ({len(out.splitlines())} lines)")
    else:
        log.warn(f"WHOIS returned no output: {err[:200]}")


def stage_subdomain_enum(domain: str, project: Path, log: ReconLogger) -> list[str]:
    log.step("Subdomain enumeration …")
    all_subs: set[str] = set()

    # subfinder — pass 1: all sources | pass 2: recursive for deeper results
    if TOOL_PATHS.get("subfinder"):
        out_file  = project / "subfinder.txt"
        out_file2 = project / "subfinder_recursive.txt"

        # Pass 1: all passive sources, high thread count
        with Spinner("subfinder pass-1 (all sources) …"):
            ok, out, err = run_cmd(
                [
                    "subfinder", "-d", domain,
                    "-silent", "-all",
                    "-t", "100",
                    "-timeout", "30",
                    "-o", str(out_file),
                ],
                log, timeout=600
            )
        subs1 = read_lines(out_file) if out_file.exists() else []
        all_subs.update(subs1)
        log.ok(f"subfinder pass-1 → {len(subs1)} subdomains")

        # Pass 2: recursive — feed discovered subs back in for deeper results
        if subs1:
            # write wordlist of just the subdomain prefixes for -dL
            sub_list_file = project / "subfinder_input.txt"
            write_lines(sub_list_file, subs1)
            with Spinner("subfinder pass-2 (recursive -dL) …"):
                ok2, out2, err2 = run_cmd(
                    [
                        "subfinder",
                        "-dL", str(sub_list_file),
                        "-silent", "-all",
                        "-t", "100",
                        "-timeout", "30",
                        "-o", str(out_file2),
                    ],
                    log, timeout=600
                )
            subs2 = read_lines(out_file2) if out_file2.exists() else []
            new_found = len(set(subs2) - all_subs)
            all_subs.update(subs2)
            log.ok(f"subfinder pass-2 → {len(subs2)} subdomains (+{new_found} new)")
    else:
        log.warn("subfinder not found — skipping")

    # amass
    if TOOL_PATHS.get("amass"):
        out_file = project / "amass.txt"
        with Spinner("amass (passive) …"):
            ok, out, err = run_cmd(
                ["amass", "enum", "-passive", "-d", domain, "-o", str(out_file)],
                log, timeout=300
            )
        if out_file.exists():
            subs = read_lines(out_file)
            all_subs.update(subs)
            log.ok(f"amass → {len(subs)} subdomains")
        else:
            log.warn(f"amass produced no output: {err[:100]}")
    else:
        log.warn("amass not found — skipping")

    # assetfinder
    if TOOL_PATHS.get("assetfinder"):
        with Spinner("assetfinder …"):
            ok, out, err = run_cmd(
                ["assetfinder", "--subs-only", domain],
                log, timeout=120
            )
        if ok and out.strip():
            subs = [l.strip() for l in out.splitlines() if l.strip()]
            all_subs.update(subs)
            log.ok(f"assetfinder → {len(subs)} subdomains")
        else:
            log.warn(f"assetfinder produced no output: {err[:100]}")
    else:
        log.warn("assetfinder not found — skipping")

    # ── crt.sh — certificate transparency logs ──────────────────────────────
    # Strategy:
    #   Round 1-4: JSON API  (fast, but crt.sh is flaky under load)
    #              tries both %25. and %. encoding — some proxies decode one
    #   Round 5:   psql direct query — bypasses the HTTP layer entirely
    #              (only works if postgresql-client is installed)
    log.info("Querying crt.sh …")

    CRT_ENDPOINTS = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q=%25.{domain}&output=json&deduplicate=Y",
    ]
    SESSION = requests.Session()
    SESSION.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
    })

    crt_subs: set[str] = set()
    crt_ok   = False

    def _parse_crt_entries(entries: list) -> set[str]:
        found: set[str] = set()
        for entry in entries:
            for field in ("name_value", "common_name"):
                raw = entry.get(field, "") or ""
                for sub in raw.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub and (sub.endswith(f".{domain}") or sub == domain):
                        found.add(sub.lower())
        return found

    # Rounds 1-4: HTTP JSON API (up to 4 attempts, exponential backoff)
    for attempt in range(4):
        for url in CRT_ENDPOINTS:
            try:
                with Spinner(f"crt.sh attempt {attempt+1} …"):
                    resp = SESSION.get(url, timeout=90, verify=True)

                if resp.status_code == 429:
                    wait = 10 * (attempt + 1)
                    log.warn(f"crt.sh rate-limited — waiting {wait}s …")
                    time.sleep(wait)
                    continue

                if resp.status_code != 200:
                    log.warn(f"crt.sh HTTP {resp.status_code} (attempt {attempt+1}) — retrying …")
                    time.sleep(2 ** attempt)
                    continue

                # Guard against empty / HTML error pages returned as 200
                content = resp.text.strip()
                if not content or content[0] != "[":
                    log.warn(f"crt.sh returned non-JSON body (attempt {attempt+1}) — retrying …")
                    time.sleep(2 ** attempt)
                    continue

                try:
                    entries = resp.json()
                except ValueError as je:
                    log.warn(f"crt.sh JSON parse error (attempt {attempt+1}): {je} — retrying …")
                    time.sleep(2 ** attempt)
                    continue

                parsed = _parse_crt_entries(entries)
                if parsed:
                    crt_subs.update(parsed)
                    crt_ok = True
                    log.ok(f"crt.sh → {len(parsed)} subdomains (attempt {attempt+1})")
                    break
                else:
                    # Valid JSON but zero results — domain may have no certs
                    log.info(f"crt.sh returned 0 results for {domain}")
                    crt_ok = True   # not a failure — just no data
                    break

            except requests.exceptions.Timeout:
                log.warn(f"crt.sh timeout (attempt {attempt+1}, 90s) — retrying …")
                time.sleep(2 ** attempt)
            except requests.exceptions.ConnectionError as ce:
                log.warn(f"crt.sh connection error (attempt {attempt+1}): {ce} — retrying …")
                time.sleep(2 ** attempt)
            except Exception as exc:
                log.warn(f"crt.sh unexpected error (attempt {attempt+1}): {exc}")
                time.sleep(2 ** attempt)

        if crt_ok:
            break

    # Round 5: psql direct query — completely bypasses HTTP flakiness
    if not crt_ok and shutil.which("psql"):
        log.info("crt.sh HTTP failed — trying psql direct query …")
        psql_query = (
            "SELECT DISTINCT lower(NAME_VALUE) "
            "FROM certificate_and_identities "
            f"WHERE plainto_tsquery('{domain}') @@ identities "
            f"AND lower(NAME_VALUE) LIKE '%.{domain}';"
        )
        with Spinner("crt.sh psql direct …"):
            ok_ps, out_ps, _ = run_cmd(
                [
                    "psql", "-t", "-A",
                    "-h", "crt.sh",
                    "-p", "5432",
                    "-U", "guest",
                    "-d", "certwatch",
                    "-c", psql_query,
                ],
                log, timeout=120
            )
        if ok_ps and out_ps.strip():
            for line in out_ps.splitlines():
                sub = line.strip().lstrip("*.")
                if sub and (sub.endswith(f".{domain}") or sub == domain):
                    crt_subs.add(sub.lower())
            log.ok(f"crt.sh psql → {len(crt_subs)} subdomains")
            crt_ok = True
        else:
            log.warn("crt.sh psql query also failed")

    if not crt_ok:
        log.warn("crt.sh unavailable after all attempts — skipping")

    if crt_subs:
        all_subs.update(crt_subs)
        (project / "crtsh.txt").write_text(
            "\n".join(sorted(crt_subs)), encoding="utf-8"
        )

    # Merge & deduplicate
    sorted_subs = sorted(all_subs)
    write_lines(project / "subdomains.txt", sorted_subs)
    log.ok(f"Total unique subdomains → {len(sorted_subs)} → subdomains.txt")
    return sorted_subs


def stage_google_dork(domain: str, project: Path, log: ReconLogger) -> list[str]:
    """
    Build Google dork queries and save them to dorks.txt.
    The file is plain text (one dork per line) so it feeds directly into
    the GF / uro filtration pipeline just like any other URL list.

    No browser is opened — manual review of dorks.txt is intentional:
    copy a query, paste it in your browser, and add any discovered
    subdomains to subdomains.txt manually before continuing.

    Dorks generated:
      site:*.target.com           — first-level subdomains
      site:*.*.target.com         — second-level subdomains
      site:*.*.*.target.com       — third-level subdomains
      site:*.target.*             — TLD wildcard
      site:target.com -www        — root domain assets
      inurl:target.com            — pages mentioning domain in URL
      intitle:"Index of" site:*.target.com  — open directories
      "target.com" filetype:pdf   — indexed PDFs
      "target.com" ext:env OR ext:log OR ext:conf  — exposed config files
    """
    log.step("Google Dorking — building dork queries …")

    tld_parts    = domain.rsplit(".", 1)   # e.g. ["example", "com"]
    tld_wildcard = f"*.{tld_parts[0]}.*"  # *.example.*

    # (label, raw dork string)
    dorks: list[tuple[str, str]] = [
        ("Subdomains 1st level",     f"site:*.{domain}"),
        ("Subdomains 2nd level",     f"site:*.*.{domain}"),
        ("Subdomains 3rd level",     f"site:*.*.*.{domain}"),
        ("TLD wildcard",             f"site:{tld_wildcard}"),
        ("Root domain excl www",     f"site:{domain} -www"),
        ("inurl mentions",           f"inurl:{domain}"),
        ("Open directories",         f'intitle:"Index of" site:*.{domain}'),
        ("Exposed PDFs",             f'"{domain}" filetype:pdf'),
        ("Exposed config/log files", f'"{domain}" ext:env OR ext:log OR ext:conf'),
    ]

    # dorks.txt  — plain dork strings (one per line), ready for filtration
    # google_dorks.txt — full Google URLs for manual copy-paste
    raw_dorks: list[str]       = []
    google_url_lines: list[str] = []

    for label, dork in dorks:
        encoded = requests.utils.quote(dork)
        google_url = f"https://www.google.com/search?q={encoded}&num=100"
        raw_dorks.append(dork)
        google_url_lines.append(f"# [{label}]\n{google_url}")
        log.ok(f"  {c(label, Color.CYAN)} → {dork}")

    # Write plain dork strings — this file enters the filtration pipeline
    dork_file = project / "dorks.txt"
    write_lines(dork_file, raw_dorks)

    # Write full Google URLs separately for manual use
    google_file = project / "google_dorks.txt"
    google_file.write_text("\n\n".join(google_url_lines) + "\n", encoding="utf-8")

    log.ok(f"{len(raw_dorks)} dorks saved → dorks.txt")
    log.info("Copy queries from google_dorks.txt and search manually for best results")

    return raw_dorks


def stage_httpx(subdomains: list[str], project: Path, log: ReconLogger):
    log.step("Running httpx for live host metadata …")
    if not TOOL_PATHS.get("httpx"):
        log.warn("httpx not found — skipping")
        return

    subs_file = project / "subdomains.txt"
    if not subs_file.exists() or not subdomains:
        log.warn("No subdomains to probe — skipping httpx")
        return

    raw_out = project / "httpx_raw.json"
    with Spinner("httpx probing all subdomains …"):
        ok, out, err = run_cmd(
            [
                "httpx",
                "-l", str(subs_file),
                "-status-code", "-title", "-location", "-tech-detect",
                "-favicon", "-content-length",
                "-json",
                "-o", str(raw_out),
                "-silent",
                "-threads", "50",
                "-timeout", "10",
                "-retries", "1",
            ],
            log, timeout=1200
        )

    if not raw_out.exists():
        log.warn(f"httpx produced no output: {err[:200]}")
        return

    info_lines: list[str] = []
    live_hosts: list[str] = []
    raw_lines = read_lines(raw_out)

    for line in raw_lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = entry.get("url", "")
        # httpx changed JSON key names across versions — try all variants
        status = (
            entry.get("status_code") or
            entry.get("status-code") or
            entry.get("status", 0)
        )
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0

        title    = entry.get("title", "") or ""
        location = (entry.get("location") or entry.get("redirect_location") or "")
        tech_raw = entry.get("tech") or entry.get("technologies") or []
        tech     = ", ".join(tech_raw) if isinstance(tech_raw, list) else str(tech_raw)
        favicon  = entry.get("favicon_hash") or entry.get("favicon-hash") or ""
        clen     = entry.get("content_length") or entry.get("content-length") or ""

        meta = (
            f"{url}"
            f"  [{status}]"
            + (f"  Title: {title}" if title else "")
            + (f"  → {location}" if location else "")
            + (f"  Tech: {tech}" if tech else "")
            + (f"  Favicon: {favicon}" if favicon else "")
            + (f"  Length: {clen}" if clen != "" else "")
        )

        if status in (200,) or (300 <= status <= 399) or status == 403:
            info_lines.append(meta)
        if status == 200:
            live_hosts.append(url)

    write_lines(project / "subdomains_info.txt", info_lines)
    write_lines(project / "live_subdomains.txt", live_hosts)
    log.ok(f"httpx → {len(info_lines)} responses (200/3xx/403) → subdomains_info.txt")
    log.ok(f"httpx → {len(live_hosts)} live (200) hosts → live_subdomains.txt")


def stage_gau(domain: str, project: Path, log: ReconLogger) -> list[str]:
    log.step("Collecting historical URLs with waybackurls …")

    raw_urls: list[str] = []
    raw_file = project / "wayback_raw.txt"

    # ── 1. waybackurls — pipe domain via stdin (correct usage) ─────────────
    if TOOL_PATHS.get("waybackurls"):
        log.info("waybackurls running (timeout: 2h) …")
        ok, out, err = run_cmd(
            ["waybackurls"],
            log, timeout=7200,
            input_data=domain
        )
        if ok and out.strip():
            wb_urls = [l.strip() for l in out.splitlines() if l.strip()]
            raw_urls.extend(wb_urls)
            log.ok(f"waybackurls → {len(wb_urls)} URLs")
        else:
            log.warn(f"waybackurls returned no output — falling back to gau …")
            # ── 2. gau fallback ─────────────────────────────────────────────
            if TOOL_PATHS.get("gau"):
                log.info("gau running (timeout: 2h) …")
                ok, out, err = run_cmd(
                    ["gau", "--threads", "10", "--timeout", "30",
                     "--blacklist", "png,jpg,gif,svg,ico,css,woff,ttf,eot,mp4,mp3,zip",
                     domain],
                    log, timeout=7200
                )
                if ok and out.strip():
                    gau_urls = [l.strip() for l in out.splitlines() if l.strip()]
                    raw_urls.extend(gau_urls)
                    log.ok(f"gau → {len(gau_urls)} URLs")
                else:
                    log.warn(f"gau also failed: {err[:80]}")
    else:
        log.warn("waybackurls not found — trying gau …")
        if TOOL_PATHS.get("gau"):
            log.info("gau running (timeout: 2h) …")
            ok, out, err = run_cmd(
                ["gau", "--threads", "10", "--timeout", "30",
                 "--blacklist", "png,jpg,gif,svg,ico,css,woff,ttf,eot,mp4,mp3,zip",
                 domain],
                log, timeout=7200
            )
            if ok and out.strip():
                gau_urls = [l.strip() for l in out.splitlines() if l.strip()]
                raw_urls.extend(gau_urls)
                log.ok(f"gau → {len(gau_urls)} URLs")
            else:
                log.warn(f"gau failed: {err[:80]}")

    if not raw_urls:
        log.warn("No historical URLs collected — skipping endpoint probing")
        (project / "active_endpoints.txt").touch()
        return []

    # ── Merge dorks.txt into the URL pool before uro ─────────────────────────
    # dorks.txt contains raw Google dork strings (not real URLs), so we convert
    # each dork into a minimal pseudo-URL that uro and gf can process:
    #   site:*.example.com  →  https://example.com/?dork=site%3A*.example.com
    # This keeps dorks in the same pipeline without confusing URL-only tools.
    dork_file = project / "dorks.txt"
    if dork_file.exists() and dork_file.stat().st_size > 0:
        dork_lines = read_lines(dork_file)
        dork_urls: list[str] = []
        for dork in dork_lines:
            encoded = requests.utils.quote(dork, safe="")
            dork_urls.append(f"https://{domain}/?dork={encoded}")
        raw_urls.extend(dork_urls)
        log.info(f"Merged {len(dork_urls)} dork entries into URL pool → uro filtration")

    write_lines(raw_file, raw_urls)
    log.ok(f"Total raw URLs → {len(raw_urls)}")

    # ── 3. Deduplicate with uro ──────────────────────────────────────────────
    deduped_urls = raw_urls
    if TOOL_PATHS.get("uro"):
        with Spinner("uro deduplicating URLs …"):
            ok, out, err = run_cmd(
                ["uro"], log, timeout=120,
                input_data="\n".join(raw_urls)
            )
        if ok and out.strip():
            deduped_urls = [l.strip() for l in out.splitlines() if l.strip()]
            log.ok(f"uro → {len(deduped_urls)} unique URLs after dedup")
        else:
            log.warn(f"uro failed — using raw list")

    deduped_file = project / "gau_deduped.txt"
    write_lines(deduped_file, deduped_urls)

    # ── 4. Probe with httpx ──────────────────────────────────────────────────
    if not TOOL_PATHS.get("httpx"):
        log.warn("httpx not available — skipping endpoint probing")
        return deduped_urls

    active_raw = project / "active_raw.json"
    with Spinner("httpx probing historical URLs …"):
        ok, out, err = run_cmd(
            [
                "httpx",
                "-l", str(deduped_file),
                "-status-code", "-json", "-silent",
                "-threads", "150", "-timeout", "8",
                "-retries", "1",
                "-o", str(active_raw),
            ],
            log, timeout=7200
        )

    active_endpoints: list[str] = []
    if active_raw.exists():
        for line in read_lines(active_raw):
            try:
                entry = json.loads(line)
                status = int(entry.get("status_code") or entry.get("status-code") or 0)
                if 200 <= status < 500:
                    active_endpoints.append(entry.get("url", ""))
            except (json.JSONDecodeError, ValueError):
                continue

    write_lines(project / "active_endpoints.txt", active_endpoints)
    log.ok(f"Active endpoints → {len(active_endpoints)} → active_endpoints.txt")
    return active_endpoints


def _ensure_active_endpoints(project: Path, log: ReconLogger):
    """Make sure active_endpoints.txt always exists so gf doesn't skip."""
    ep_file = project / "active_endpoints.txt"
    if not ep_file.exists():
        ep_file.touch()
        log.debug("Created empty active_endpoints.txt")


def stage_params(active_endpoints: list[str], project: Path, log: ReconLogger):
    log.step("Extracting URL parameters …")
    # Store full URLs with each parameter isolated and value blanked for fuzzing
    # Format: https://target.com/path?param=
    param_urls: set[str] = set()
    for url in active_endpoints:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if not qs:
                continue
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in qs.keys():
                # Build a clean URL with only this param and an empty value
                fuzz_url = f"{base}?{param}="
                param_urls.add(fuzz_url)
        except Exception:
            continue

    write_lines(project / "params.txt", sorted(param_urls))
    log.ok(f"Parameters extracted → {len(param_urls)} → params.txt")


def stage_gf(project: Path, log: ReconLogger):
    log.step("Running GF patterns on active endpoints …")
    if not TOOL_PATHS.get("gf"):
        log.warn("gf not found — skipping")
        return

    endpoints_file = project / "active_endpoints.txt"
    # Fallback: if active_endpoints is empty, try live_subdomains
    if not endpoints_file.exists() or endpoints_file.stat().st_size == 0:
        fallback = project / "live_subdomains.txt"
        if fallback.exists() and fallback.stat().st_size > 0:
            log.warn("active_endpoints.txt empty — falling back to live_subdomains.txt for gf")
            endpoints_file = fallback
        else:
            log.warn("No endpoints available for gf — skipping")
            return

    # Build the combined input: active_endpoints + dorks (as pseudo-URLs)
    # dorks.txt is already merged into the URL pool via stage_gau, but we
    # also feed the raw dork strings directly so gf pattern keywords
    # (e.g. "sqli", "xss") can match dork labels as an extra signal.
    combined_input_lines: list[str] = list(read_lines(endpoints_file))
    dork_file = project / "dorks.txt"
    if dork_file.exists() and dork_file.stat().st_size > 0:
        combined_input_lines.extend(read_lines(dork_file))
        log.info(f"GF input: {len(combined_input_lines)} lines (endpoints + dorks)")

    combined_input = "\n".join(combined_input_lines)

    patterns = ["xss", "sqli", "ssrf", "redirect", "lfi", "rce", "upload", "idor", "debug", "aws-keys"]
    gf_dir = project / "gf"

    for pattern in patterns:
        out_file = gf_dir / f"{pattern}.txt"
        with Spinner(f"gf {pattern} …"):
            ok, out, err = run_cmd(
                ["gf", pattern],
                log, timeout=60,
                input_data=combined_input
            )
        if ok and out.strip():
            matches = [l.strip() for l in out.splitlines() if l.strip()]
            write_lines(out_file, matches)
            log.ok(f"gf {c(pattern, Color.CYAN)} → {len(matches)} matches")
        else:
            log.debug(f"gf {pattern} → no matches")


def stage_katana(domain: str, project: Path, log: ReconLogger) -> list[str]:
    log.step("Crawling with Katana …")
    if not TOOL_PATHS.get("katana"):
        log.warn("katana not found — skipping")
        return []

    js_dir = project / "js"
    all_js: set[str] = set()

    # ── Build crawl targets: main domain + all live subdomains ───────────────
    targets: list[str] = []
    live_file = project / "live_subdomains.txt"
    if live_file.exists() and live_file.stat().st_size > 0:
        targets = read_lines(live_file)
        log.info(f"katana will crawl {len(targets)} live hosts")
    else:
        targets = [f"https://{domain}", f"http://{domain}"]
        log.info("katana crawling main domain only (no live_subdomains.txt)")

    # Limit to 50 targets to avoid extremely long runs
    if len(targets) > 50:
        log.info(f"Limiting katana to first 50 live hosts (total: {len(targets)})")
        targets = targets[:50]

    # Write targets to a file for -list flag
    targets_file = project / "katana_targets.txt"
    write_lines(targets_file, targets)

    katana_out = project / "katana.txt"

    with Spinner("katana crawling all live hosts …"):
        ok, out, err = run_cmd(
            [
                "katana",
                "-list", str(targets_file),
                "-depth", "5",
                "-js-crawl",
                "-known-files", "all",
                "-automatic-form-fill",
                "-silent",
                "-o", str(katana_out),
                "-concurrency", "30",
                "-parallelism", "10",
                "-timeout", "20",
                "-retry", "2",
                "-display-out-scope",
            ],
            log, timeout=1800
        )

    # Collect JS from katana output
    if katana_out.exists():
        all_urls = read_lines(katana_out)
        for u in all_urls:
            if u.lower().endswith(".js"):
                all_js.add(u)
        log.ok(f"katana → {len(all_urls)} URLs, {len(all_js)} JS files")
    else:
        log.warn(f"katana produced no output: {err[:100]}")

    # ── Also collect JS from wayback/gau deduped URLs ────────────────────────
    deduped_file = project / "gau_deduped.txt"
    if deduped_file.exists() and deduped_file.stat().st_size > 0:
        wayback_js = [
            u for u in read_lines(deduped_file)
            if u.lower().endswith(".js") and domain in u
        ]
        before = len(all_js)
        all_js.update(wayback_js)
        new_js = len(all_js) - before
        if new_js:
            log.ok(f"wayback JS → +{new_js} additional JS files from historical URLs")

    # ── Also collect JS from active endpoints ────────────────────────────────
    ep_file = project / "active_endpoints.txt"
    if ep_file.exists() and ep_file.stat().st_size > 0:
        ep_js = [
            u for u in read_lines(ep_file)
            if u.lower().endswith(".js")
        ]
        before = len(all_js)
        all_js.update(ep_js)
        new_js = len(all_js) - before
        if new_js:
            log.ok(f"endpoints JS → +{new_js} additional JS files from active endpoints")

    js_files = sorted(all_js)
    write_lines(js_dir / "js_files.txt", js_files)
    log.ok(f"Total unique JS files → {len(js_files)} → js/js_files.txt")
    return js_files


def _analyze_single_js(js_url: str, log: ReconLogger) -> dict:
    """Analyze one JS file — returns dict of results.
    Uses xnLinkFinder (best for endpoints/URLs) + inline regex (best for secrets).
    LinkFinder and SecretFinder removed to reduce CPU/memory load.
    """
    result = {"urls": [], "endpoints": [], "interesting": [], "secrets": []}

    # ── xnLinkFinder — endpoints & URLs (better than LinkFinder) ────────────
    if TOOL_PATHS.get("xnLinkFinder"):
        ok, out, err = run_cmd(
            ["python3", TOOL_PATHS["xnLinkFinder"], "-i", js_url, "-sp", js_url, "-q"],
            log, timeout=90
        )
        if ok and out.strip():
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("/"):
                    result["endpoints"].append(line)
                elif line.startswith("http"):
                    result["urls"].append(line)

    # ── Inline regex — secrets (more patterns than SecretFinder) ────────────
    result["secrets"] = _extract_secrets_from_js(js_url, log)

    return result


def stage_js_analysis(js_files: list[str], project: Path, log: ReconLogger):
    log.step("Analyzing JavaScript files …")
    if not js_files:
        log.warn("No JS files to analyze — skipping")
        return

    js_dir = project / "js"
    js_urls_all: list[str]     = []
    endpoints_all: list[str]   = []
    interesting_all: list[str] = []
    secrets_all: list[dict]    = []

    total = len(js_files)
    log.info(f"Analyzing {total} JS files (concurrent, 10 workers) …")

    # Run analysis concurrently — 10 workers for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_analyze_single_js, js_url, log): js_url
                   for js_url in js_files}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            js_url = futures[future]
            log.debug(f"[{done}/{total}] {js_url}")
            try:
                res = future.result()
                js_urls_all.extend(res["urls"])
                endpoints_all.extend(res["endpoints"])
                interesting_all.extend(res["interesting"])
                secrets_all.extend(res["secrets"])
            except Exception as exc:
                log.warn(f"JS analysis error for {js_url}: {exc}")

    write_lines(js_dir / "js_urls.txt",     sorted(set(js_urls_all)))
    write_lines(js_dir / "endpoints.txt",   sorted(set(endpoints_all)))
    write_lines(js_dir / "interesting.txt", sorted(set(interesting_all)))

    secrets_path = js_dir / "secrets.json"
    secrets_path.write_text(
        json.dumps(secrets_all, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    log.ok(f"JS analysis → {len(set(js_urls_all))} URLs, {len(set(endpoints_all))} endpoints, "
           f"{len(set(interesting_all))} interesting, {len(secrets_all)} secrets")


# ─────────────────────────────────────────────
#  Inline secret pattern extraction
# ─────────────────────────────────────────────
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key",        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")),
    ("AWS Secret Key",        re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([\w/+]{40})['\"]")),
    ("Google API Key",        re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Firebase Key",          re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}")),
    ("GitHub Token",          re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}")),
    ("JWT Token",             re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Bearer Token",          re.compile(r"(?i)bearer\s+([A-Za-z0-9\-_\.~\+\/]{20,})")),
    ("Slack Token",           re.compile(r"xox[baprs]-([0-9a-zA-Z]{10,48})")),
    ("Stripe Live Key",       re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Public Key",     re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("Twilio Account SID",    re.compile(r"AC[a-z0-9]{32}")),
    ("Twilio Auth Token",     re.compile(r"(?i)twilio.{0,30}['\"]([\w]{32})['\"]")),
    ("Private Key Header",    re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----")),
    ("Mailgun API Key",       re.compile(r"key-[0-9a-zA-Z]{32}")),
    ("Heroku API Key",        re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")),
    ("SendGrid API Key",      re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}")),
    ("Shopify Token",         re.compile(r"shpss_[a-fA-F0-9]{32}|shpat_[a-fA-F0-9]{32}")),
]

def _extract_secrets_from_js(js_url: str, log: ReconLogger) -> list[dict]:
    secrets: list[dict] = []
    try:
        resp = requests.get(
            js_url, timeout=15, verify=False,
            headers={"User-Agent": "Mozilla/5.0 ReconAuto/1.0"}
        )
        if resp.status_code != 200 or not resp.text:
            return []
        content = resp.text
    except Exception:
        return []

    for category, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            secrets.append({
                "category": category,
                "value":    match.group(0)[:80],
                "source":   js_url,
            })
    return secrets


# ─────────────────────────────────────────────
#  EyeWitness — screenshot & HTML report
# ─────────────────────────────────────────────
def _find_eyewitness() -> Optional[tuple[list[str], str]]:
    """
    Locate the EyeWitness executable and return the command prefix needed
    to run it, along with the install path for logging.

    EyeWitness ships in several forms depending on how it was installed:
      - apt (Kali):   /usr/bin/eyewitness     → direct binary
      - from source:  ~/tools/EyeWitness/Python/EyeWitness.py
                      + ~/tools/EyeWitness/eyewitness-venv/bin/python
                      (modern versions require activating the venv)

    Returns (cmd_prefix, display_path) or None if not found.
    """
    # 1. System binary installed by apt (simplest — just call it directly)
    for name in ("eyewitness", "EyeWitness"):
        path = shutil.which(name)
        if path:
            return [path], path

    # 2. Source install — scan common locations for EyeWitness.py
    candidate_dirs = [
        Path.home() / "tools" / "EyeWitness",
        Path("/opt/EyeWitness"),
        Path("/opt/eyewitness"),
        Path.home() / "EyeWitness",
    ]
    for base in candidate_dirs:
        # Modern layout:  base/Python/EyeWitness.py  +  base/eyewitness-venv/
        script = base / "Python" / "EyeWitness.py"
        venv_py = base / "eyewitness-venv" / "bin" / "python"
        if script.exists():
            if venv_py.exists():
                # Run inside the venv — this is required by the modern version
                return [str(venv_py), str(script)], str(script)
            else:
                # Legacy layout or venv not yet created — try system python3
                return ["python3", str(script)], str(script)

        # Legacy layout:  base/Python3/EyeWitness.py
        script_legacy = base / "Python3" / "EyeWitness.py"
        if script_legacy.exists():
            return ["python3", str(script_legacy)], str(script_legacy)

    return None


def stage_eyewitness(project: Path, log: ReconLogger):
    """
    Run EyeWitness against all live subdomains (HTTP 200) and produce a
    self-contained HTML report with screenshots.

    Supported arguments (current RedSiege/EyeWitness Python version):
      -f FILE          input list of URLs
      -d DIR           output directory
      --web            web screenshot mode
      --no-prompt      skip interactive confirmation
      --timeout N      seconds to wait per host (default 7)
      --threads N      concurrent workers (default: 2×CPU cores, max 20)
      --delay N        delay between requests in seconds
      --max-retries N  retries on timeout

    NOT supported (removed in modern version):
      --prepend-https, --resolve, --cycle
    """
    log.step("Running EyeWitness for screenshots …")

    found = _find_eyewitness()
    if not found:
        log.warn(
            "eyewitness not found — skipping  "
            "(install: cd ~/tools/EyeWitness/setup && sudo ./setup.sh)"
        )
        return

    cmd_prefix, display_path = found
    log.info(f"EyeWitness binary → {display_path}")

    # Prefer live_subdomains.txt (HTTP 200 only); fall back to subdomains_info.txt
    targets_file = project / "live_subdomains.txt"
    if not targets_file.exists() or targets_file.stat().st_size == 0:
        targets_file = project / "subdomains_info.txt"
    if not targets_file.exists() or targets_file.stat().st_size == 0:
        log.warn("No live hosts file found for EyeWitness — skipping")
        return

    ew_out_dir = project / "eyewitness"
    ew_out_dir.mkdir(exist_ok=True)

    log.info(f"EyeWitness → targets from {targets_file.name}, output → eyewitness/")

    cmd = cmd_prefix + [
        "--web",                        # web screenshot mode
        "-f", str(targets_file),        # input list of URLs
        "-d", str(ew_out_dir),          # output directory
        "--no-prompt",                  # skip interactive prompt
        "--timeout", "15",              # seconds per host
        "--threads", "10",              # concurrent workers
        "--delay", "0",                 # no artificial delay between hosts
        "--max-retries", "1",           # one retry on timeout
    ]

    with Spinner("EyeWitness taking screenshots …"):
        ok, out, err = run_cmd(cmd, log, timeout=3600)

    # EyeWitness writes report.html (sometimes in a dated subdirectory)
    report_candidates = (
        list(ew_out_dir.glob("report.html")) +
        list(ew_out_dir.glob("*/report.html")) +
        list(ew_out_dir.glob("**/*.html"))
    )
    report_path = report_candidates[0] if report_candidates else None

    # Count screenshots (.png in any subdirectory)
    screenshots = list(ew_out_dir.glob("**/*.png"))

    if report_path and report_path.exists():
        log.ok(f"EyeWitness complete → {len(screenshots)} screenshots")
        log.ok(f"HTML report → {report_path}")
        try:
            webbrowser.open(report_path.as_uri())
            log.info("Opened EyeWitness report in browser")
        except Exception:
            pass
    elif screenshots:
        # Screenshots taken but no report found — partial success
        log.ok(f"EyeWitness partial → {len(screenshots)} screenshots, no report.html")
    else:
        log.warn(f"EyeWitness produced no output: {err[:300]}")


# ─────────────────────────────────────────────
#  Summary report
# ─────────────────────────────────────────────
def print_summary(domain: str, project: Path, log: ReconLogger):
    log.step("Generating Recon Summary …")

    def _count(filename: str) -> int:
        return len(read_lines(project / filename))

    def _count_js(filename: str) -> int:
        return len(read_lines(project / "js" / filename))

    def _count_secrets() -> int:
        sp = project / "js" / "secrets.json"
        if not sp.exists():
            return 0
        try:
            return len(json.loads(sp.read_text(encoding="utf-8")))
        except Exception:
            return 0

    def _count_httpx_status(code_range) -> int:
        info = project / "subdomains_info.txt"
        if not info.exists():
            return 0
        count = 0
        for line in read_lines("subdomains_info.txt"):
            # handled below
            pass
        lines = read_lines(info)
        for line in lines:
            m = re.search(r'\[(\d{3})\]', line)
            if m and int(m.group(1)) in code_range:
                count += 1
        return count

    # Simpler aggregates from files
    total_subs    = _count("subdomains.txt")
    live_hosts    = _count("live_subdomains.txt")
    gau_deduped   = _count("gau_deduped.txt") or _count("gau_raw.txt")
    active_ep     = _count("active_endpoints.txt")
    params        = _count("params.txt")
    js_files      = _count_js("js_files.txt")
    js_endpoints  = _count_js("endpoints.txt")
    secrets       = _count_secrets()

    # 3xx and 403 from subdomains_info
    redirects = fours = 0
    info_path = project / "subdomains_info.txt"
    if info_path.exists():
        for line in read_lines(info_path):
            m = re.search(r'\[(\d{3})\]', line)
            if m:
                s = int(m.group(1))
                if 300 <= s <= 399: redirects += 1
                if s == 403:        fours += 1

    sep = c("─" * 52, Color.GREY)
    title = c("  RECON SUMMARY", Color.CYAN, bold=True)
    domain_line = c(f"  Target: {domain}", Color.WHITE, bold=True)

    print(f"\n{sep}")
    print(title)
    print(domain_line)
    print(sep)

    rows = [
        ("Subdomains discovered",     total_subs,   Color.CYAN),
        ("Live hosts (HTTP 200)",      live_hosts,   Color.GREEN),
        ("Redirects (3xx)",            redirects,    Color.YELLOW),
        ("Forbidden (403)",            fours,        Color.YELLOW),
        ("Historical URLs (GAU)",      gau_deduped,  Color.BLUE),
        ("Active endpoints",           active_ep,    Color.BLUE),
        ("Unique parameters",          params,       Color.MAGENTA),
        ("JavaScript files found",     js_files,     Color.CYAN),
        ("JS-extracted endpoints",     js_endpoints, Color.CYAN),
        ("Secrets / interesting",      secrets,      Color.RED if secrets else Color.GREY),
    ]

    for label, value, color in rows:
        val_str = c(str(value), color, bold=True)
        print(f"  {label:<30} {val_str}")

    print(sep)
    print(c(f"  Output directory: {project}", Color.GREY))
    print(c(f"  Log file:         {project}/recon.log", Color.GREY))
    print(sep + "\n")


# ─────────────────────────────────────────────
#  Main orchestrator
# ─────────────────────────────────────────────
def main():
    banner()

    # Input
    print(c("  [?] Enter the target domain (e.g. example.com): ", Color.CYAN, bold=True), end="")
    try:
        raw_input = input().strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    domain = clean_domain(raw_input)
    if not domain:
        print(c("  [✘] No domain provided. Exiting.", Color.RED))
        sys.exit(1)

    print(c(f"\n  Target set to: {domain}\n", Color.GREEN, bold=True))

    # Workspace — create directory first so we can open the log file
    base_dir = Path.cwd()
    project  = base_dir / domain
    project.mkdir(parents=True, exist_ok=True)
    for sub in ["js", "gf", "secrets", "eyewitness"]:
        (project / sub).mkdir(exist_ok=True)

    log = ReconLogger(project / "recon.log")
    log.ok(f"Workspace ready → {project}")
    log.ok(f"Recon session started for {c(domain, Color.CYAN, bold=True)}")
    log.info(f"Workspace: {project}")

    # Tool detection
    required_tools = [
        "whois", "subfinder", "amass", "assetfinder",
        "httpx", "waybackurls", "gau", "uro", "gf", "katana",
        "xnLinkFinder", "eyewitness",
    ]
    TOOL_PATHS.update(detect_tools(required_tools, log))

    print()

    # Stage 1 – open browser tabs + Google dorks
    stage_open_browser(domain, log)
    print()

    # Stage 2 – Google Dorking (opens dork queries in browser tabs)
    stage_google_dork(domain, project, log)
    print()

    # Stage 3 – WHOIS
    stage_whois(domain, project, log)
    print()

    # Stage 4 – Subdomain enumeration
    subdomains = stage_subdomain_enum(domain, project, log)
    print()

    # Stage 5 – httpx
    stage_httpx(subdomains, project, log)
    print()

    # Stage 6 – EyeWitness screenshots (right after we know live hosts)
    stage_eyewitness(project, log)
    print()

    # Stage 7 – GAU + uro + active endpoints
    active_endpoints = stage_gau(domain, project, log)
    print()

    # Stage 8 – Parameter extraction
    stage_params(active_endpoints, project, log)
    print()

    # Stage 9 – GF patterns
    stage_gf(project, log)
    print()

    # Stage 10 – Katana crawl
    js_files = stage_katana(domain, project, log)
    print()

    # Stage 11 – JS analysis
    stage_js_analysis(js_files, project, log)
    print()

    # Summary
    print_summary(domain, project, log)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n\n  [!] Interrupted by user. Partial results saved.", Color.YELLOW))
        sys.exit(130)
