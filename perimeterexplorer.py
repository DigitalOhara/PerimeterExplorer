#!/usr/bin/env python3
"""
PerimeterExplorer - Subdomain Enumeration Tool
GitHub: https://github.com/DigitalOhara/PerimeterExplorer

Combines multiple subdomain enumeration tools and APIs into a single workflow.
Outputs results in .txt, .csv, and .html formats.
"""

import os
import sys
import subprocess
import json
import csv
import argparse
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[!] Run: pip install -r requirements.txt")
    sys.exit(1)

# ─── ANSI / colour helpers ─────────────────────────────────────────────────────

def info(msg):   print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
def success(msg):print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):   print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def error(msg):  print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

BANNER = f"""{Fore.CYAN}
  ____           _                      _
 |  _ \\ ___ _ __(_)_ __ ___   ___  _ __| |
 | |_) / _ \\ '__| | '_ ` _ \\ / _ \\| '__| |
 |  __/  __/ |  | | | | | | |  __/| |  |_|
 |_|   \\___|_|  |_|_| |_| |_|\\___|_|  (_)
  _____            _
 | ____|_  ___ __ | | ___  _ __ ___ _ __
 |  _| \\ \\/ / '_ \\| |/ _ \\| '__/ _ \\ '__|
 | |___ >  <| |_) | | (_) | | |  __/ |
 |_____/_/\\_\\ .__/|_|\\___/|_|  \\___|_|
            |_|
{Style.RESET_ALL}
  {Fore.GREEN}Subdomain Enumeration Tool{Style.RESET_ALL}
  {Fore.WHITE}github.com/DigitalOhara/PerimeterExplorer{Style.RESET_ALL}
  {"─" * 50}
"""

# ─── Subdomain validation helper ──────────────────────────────────────────────

SUBDOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

def is_valid_subdomain(sub, domain):
    sub = sub.strip().lower().rstrip('.')
    if not sub:
        return False
    if not SUBDOMAIN_RE.match(sub):
        return False
    return sub.endswith(f'.{domain}') or sub == domain


def clean_subdomains(raw_list, domain):
    """Deduplicate, validate and sort a list of subdomain strings."""
    seen = set()
    out  = []
    for line in raw_list:
        line = line.strip().lower().rstrip('.')
        if line and line not in seen and is_valid_subdomain(line, domain):
            seen.add(line)
            out.append(line)
    return sorted(out)


# ─── Main scanner class ────────────────────────────────────────────────────────

class PerimeterExplorer:
    def __init__(self, domain: str, output_dir: Path,
                 vt_api_key: str = None, wordlist: str = None,
                 skip_active: bool = False):
        self.domain       = domain.lower().strip()
        self.output_dir   = output_dir
        self.vt_api_key   = vt_api_key
        self.wordlist     = wordlist
        self.skip_active  = skip_active
        self.tool_results = {}      # {tool_name: [subdomain, ...]}
        self.all_subs     = set()
        output_dir.mkdir(parents=True, exist_ok=True)

    # ── helpers ────────────────────────────────────────────────────────────────

    def _tmp(self, name):
        """Return a Path for an intermediate output file inside output_dir."""
        return self.output_dir / name

    def _run(self, cmd, timeout=300):
        """Run a shell command; return (stdout, stderr, returncode)."""
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            warn(f"Command timed out: {cmd[:80]}")
            return "", "", -1
        except Exception as exc:
            warn(f"Command error: {exc}")
            return "", "", -1

    def _tool_available(self, name):
        """Return True if `name` is on PATH."""
        from shutil import which
        return which(name) is not None

    def _record(self, tool_name, subdomains):
        cleaned = clean_subdomains(subdomains, self.domain)
        self.tool_results[tool_name] = cleaned
        self.all_subs.update(cleaned)
        success(f"{tool_name}: {len(cleaned)} subdomains found")
        return cleaned

    # ── tool runners ──────────────────────────────────────────────────────────

    def run_subfinder(self):
        tool = "subfinder"
        if not self._tool_available(tool):
            warn(f"{tool} not found — skipping"); return
        info(f"Running {tool}...")
        out_file = self._tmp("subfinder.txt")
        self._run(
            f"subfinder -d {self.domain} -all -recursive -o {out_file} -silent",
            timeout=600
        )
        lines = out_file.read_text().splitlines() if out_file.exists() else []
        self._record(tool, lines)

    def run_assetfinder(self):
        tool = "assetfinder"
        if not self._tool_available(tool):
            warn(f"{tool} not found — skipping"); return
        info(f"Running {tool}...")
        out_file = self._tmp("assetfinder.txt")
        stdout, _, _ = self._run(
            f"assetfinder --subs-only {self.domain}", timeout=300
        )
        out_file.write_text(stdout)
        self._record(tool, stdout.splitlines())

    def run_findomain(self):
        tool = "findomain"
        if not self._tool_available(tool):
            warn(f"{tool} not found — skipping"); return
        info(f"Running {tool}...")
        out_file = self._tmp("findomain.txt")
        stdout, _, _ = self._run(
            f"findomain -t {self.domain} --quiet", timeout=300
        )
        out_file.write_text(stdout)
        self._record(tool, stdout.splitlines())

    def run_amass_passive(self):
        tool = "amass"
        if not self._tool_available(tool):
            warn(f"{tool} not found — skipping amass passive"); return
        info("Running amass (passive)...")
        out_file = self._tmp("amass.txt")
        stdout, _, _ = self._run(
            f"amass enum -passive -d {self.domain}", timeout=600
        )
        # strip leading bracket notation: [tag] subdomain.domain.com
        subs = []
        for line in stdout.splitlines():
            parts = re.split(r'\]', line)
            if len(parts) >= 2:
                subs.append(parts[-1].strip())
            else:
                subs.append(line.strip())
        out_file.write_text('\n'.join(subs))
        self._record("amass_passive", subs)

    def run_amass_active(self):
        if self.skip_active:
            warn("Skipping amass active (--skip-active flag set)"); return
        tool = "amass"
        if not self._tool_available(tool):
            warn(f"{tool} not found — skipping amass active"); return
        info("Running amass (active) — this may take a while...")
        out_file = self._tmp("amass_active.txt")
        stdout, _, _ = self._run(
            f"amass enum -active -d {self.domain}", timeout=900
        )
        subs = []
        for line in stdout.splitlines():
            parts = re.split(r'\]', line)
            if len(parts) >= 2:
                subs.append(parts[-1].strip())
            else:
                subs.append(line.strip())
        out_file.write_text('\n'.join(subs))
        self._record("amass_active", subs)

    def run_crtsh(self):
        info("Querying crt.sh (certificate transparency)...")
        out_file = self._tmp("crtsh.txt")
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=30,
                headers={"User-Agent": "PerimeterExplorer/1.0"}
            )
            resp.raise_for_status()
            data = resp.json()
            subs = []
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lstrip("*.")
                    subs.append(line)
            out_file.write_text('\n'.join(subs))
            self._record("crtsh", subs)
        except Exception as exc:
            warn(f"crt.sh error: {exc}")

    def run_wayback(self):
        info("Querying Wayback Machine (web.archive.org)...")
        out_file = self._tmp("wayback.txt")
        try:
            url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey"
            )
            resp = requests.get(url, timeout=60,
                                headers={"User-Agent": "PerimeterExplorer/1.0"})
            resp.raise_for_status()
            subs = []
            for line in resp.text.splitlines():
                # strip scheme
                line = re.sub(r'^https?://', '', line)
                # strip path
                line = line.split('/')[0]
                # strip port
                line = line.split(':')[0]
                # strip leading www.
                line = re.sub(r'^www\.', '', line)
                subs.append(line.strip())
            out_file.write_text('\n'.join(subs))
            self._record("wayback", subs)
        except Exception as exc:
            warn(f"Wayback Machine error: {exc}")

    def run_virustotal(self):
        info("Querying VirusTotal...")
        out_file = self._tmp("virustotal.txt")
        subs = []
        try:
            if self.vt_api_key:
                # Official API v3
                headers = {"x-apikey": self.vt_api_key}
                cursor  = None
                while True:
                    params = {"limit": 40}
                    if cursor:
                        params["cursor"] = cursor
                    resp = requests.get(
                        f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains",
                        headers=headers, params=params, timeout=30
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    for item in data.get("data", []):
                        subs.append(item.get("id", ""))
                    cursor = data.get("meta", {}).get("cursor")
                    if not cursor or not data.get("data"):
                        break
                    time.sleep(0.5)   # be polite
            else:
                # Public UI endpoint (no key, limited results)
                resp = requests.get(
                    f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40",
                    timeout=30,
                    headers={"User-Agent": "PerimeterExplorer/1.0"}
                )
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("data", []):
                    subs.append(item.get("id", ""))
            out_file.write_text('\n'.join(subs))
            self._record("virustotal", subs)
        except Exception as exc:
            warn(f"VirusTotal error: {exc}")

    def run_dnsrecon(self):
        tool = "dnsrecon"
        if not self._tool_available(tool):
            warn(f"{tool} not found — skipping"); return
        info(f"Running {tool}...")
        xml_file = self._tmp("dnsrecon.xml")
        self._run(
            f"dnsrecon -d {self.domain} -t std -x {xml_file}", timeout=300
        )
        subs = []
        if xml_file.exists():
            try:
                tree = ET.parse(xml_file)
                for record in tree.iter('record'):
                    name = record.get('name', '')
                    if name:
                        subs.append(name.strip())
            except ET.ParseError:
                warn("dnsrecon: could not parse XML output")
        self._record("dnsrecon", subs)

    def run_fierce(self):
        if self.skip_active:
            warn("Skipping fierce (--skip-active flag set)"); return
        tool = "fierce"
        if not self._tool_available(tool):
            warn(f"{tool} not found — skipping"); return
        info(f"Running {tool}...")
        out_file = self._tmp("fierce.txt")
        if self.wordlist and Path(self.wordlist).exists():
            cmd = f"fierce --domain {self.domain} --subdomains {self.wordlist}"
        else:
            if self.wordlist:
                warn(f"Wordlist not found: {self.wordlist} — running fierce without wordlist")
            cmd = f"fierce --domain {self.domain}"
        stdout, _, _ = self._run(cmd, timeout=600)
        out_file.write_text(stdout)
        # fierce output lines like:  Found: sub.domain.com. (x.x.x.x)
        subs = []
        for line in stdout.splitlines():
            m = re.search(r'Found:\s+([\w.\-]+)', line)
            if m:
                subs.append(m.group(1).rstrip('.'))
        self._record("fierce", subs)

    # ── run all ───────────────────────────────────────────────────────────────

    def run_all(self):
        runners = [
            self.run_subfinder,
            self.run_assetfinder,
            self.run_findomain,
            self.run_amass_passive,
            self.run_amass_active,
            self.run_crtsh,
            self.run_wayback,
            self.run_virustotal,
            self.run_dnsrecon,
            self.run_fierce,
        ]
        for runner in runners:
            try:
                runner()
            except Exception as exc:
                error(f"Unexpected error in {runner.__name__}: {exc}")

    # ── output generation ─────────────────────────────────────────────────────

    def _sorted_all(self):
        return sorted(self.all_subs)

    def write_txt(self, base_name: str) -> Path:
        path = self.output_dir / f"{base_name}.txt"
        content = [
            f"# PerimeterExplorer - Subdomain Enumeration Report",
            f"# Target  : {self.domain}",
            f"# Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Total   : {len(self.all_subs)} unique subdomains",
            f"# Sources : {', '.join(sorted(self.tool_results.keys()))}",
            "",
        ] + self._sorted_all()
        path.write_text('\n'.join(content))
        return path

    def write_csv(self, base_name: str) -> Path:
        path = self.output_dir / f"{base_name}.csv"
        # Build a source map: subdomain -> list of tools that found it
        source_map = {}
        for tool, subs in self.tool_results.items():
            for sub in subs:
                source_map.setdefault(sub, []).append(tool)
        with open(path, 'w', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(["subdomain", "sources", "source_count"])
            for sub in self._sorted_all():
                srcs = source_map.get(sub, [])
                writer.writerow([sub, ' | '.join(sorted(srcs)), len(srcs)])
        return path

    def write_html(self, base_name: str) -> Path:
        path = self.output_dir / f"{base_name}.html"

        # Build source map
        source_map = {}
        for tool, subs in self.tool_results.items():
            for sub in subs:
                source_map.setdefault(sub, []).append(tool)

        # Tool summary rows
        tool_rows = ""
        for tool in sorted(self.tool_results.keys()):
            count = len(self.tool_results[tool])
            badge_color = "#238636" if count > 0 else "#6e7681"
            tool_rows += (
                f'<tr><td class="tool-name">{tool}</td>'
                f'<td><span class="badge" style="background:{badge_color}">'
                f'{count}</span></td></tr>\n'
            )

        # Subdomain table rows
        sub_rows = ""
        for i, sub in enumerate(self._sorted_all(), 1):
            srcs = sorted(source_map.get(sub, []))
            tags = " ".join(
                f'<span class="source-tag">{s}</span>' for s in srcs
            )
            sub_rows += (
                f'<tr><td class="row-num">{i}</td>'
                f'<td class="subdomain">{sub}</td>'
                f'<td>{tags}</td>'
                f'<td class="count">{len(srcs)}</td></tr>\n'
            )

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PerimeterExplorer &mdash; {self.domain}</title>
<style>
  :root {{
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --text:     #c9d1d9;
    --muted:    #8b949e;
    --green:    #3fb950;
    --cyan:     #39d353;
    --accent:   #58a6ff;
    --red:      #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Courier New', Courier, monospace;
    padding: 2rem;
    line-height: 1.6;
  }}
  header {{
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
    padding-bottom: 1.5rem;
  }}
  header pre {{
    color: var(--cyan);
    font-size: 0.65rem;
    line-height: 1.2;
    margin-bottom: 1rem;
  }}
  h1 {{ font-size: 1.6rem; color: var(--accent); margin-bottom: 0.4rem; }}
  h2 {{ font-size: 1.1rem; color: var(--muted); margin: 1.5rem 0 0.75rem; }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .meta-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
  }}
  .meta-card .label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; }}
  .meta-card .value {{ font-size: 1.4rem; color: var(--green); font-weight: bold; }}
  .section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 2rem;
    overflow: hidden;
  }}
  .section-header {{
    background: #1c2128;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{
    background: #1c2128;
    padding: 0.6rem 1rem;
    text-align: left;
    color: var(--muted);
    font-weight: normal;
    border-bottom: 1px solid var(--border);
    font-size: 0.75rem;
    text-transform: uppercase;
  }}
  td {{ padding: 0.5rem 1rem; border-bottom: 1px solid #21262d; vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1c2128; }}
  .row-num  {{ color: var(--muted); width: 3rem; text-align: right; }}
  .subdomain {{ color: var(--accent); font-weight: bold; }}
  .count    {{ color: var(--muted); text-align: center; width: 4rem; }}
  .tool-name {{ color: var(--text); }}
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 20px;
    font-size: 0.75rem;
    color: #fff;
    font-weight: bold;
  }}
  .source-tag {{
    display: inline-block;
    background: #1f2d3d;
    border: 1px solid #3d6a9e;
    color: #79b8ff;
    border-radius: 4px;
    padding: 0.1rem 0.45rem;
    font-size: 0.7rem;
    margin: 0.1rem 0.15rem;
  }}
  .search-box {{
    width: 100%;
    background: #161b22;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.9rem;
    color: var(--text);
    font-family: inherit;
    font-size: 0.85rem;
    margin-bottom: 1rem;
    outline: none;
  }}
  .search-box:focus {{ border-color: var(--accent); }}
  footer {{
    text-align: center;
    color: var(--muted);
    font-size: 0.75rem;
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
  }}
  footer a {{ color: var(--accent); text-decoration: none; }}
</style>
</head>
<body>

<header>
<pre>
  ____           _                      _
 |  _ \\  ___ _ __(_)_ __ ___   ___  _ __| |
 | |_) |/ _ \\ '__| | '_ ` _ \\ / _ \\| '__| |
 |  __/|  __/ |  | | | | | | |  __/| |  |_|
 |_|    \\___|_|  |_|_| |_| |_|\\___|_|  (_)
  _____            _
 | ____|_  ___ __ | | ___  _ __ ___ _ __
 |  _| \\ \\/ / '_ \\| |/ _ \\| '__/ _ \\ '__|
 | |___ >  &lt;| |_) | | (_) | | |  __/ |
 |_____/_/\\_\\ .__/|_|\\___/|_|  \\___|_|
            |_|
</pre>
<h1>Subdomain Enumeration Report</h1>
<div style="color: var(--muted); font-size: 0.9rem;">
  Target: <span style="color: var(--accent)">{self.domain}</span>
  &nbsp;&nbsp;|&nbsp;&nbsp;
  Generated: <span style="color: var(--text)">{timestamp}</span>
</div>
</header>

<div class="meta-grid">
  <div class="meta-card">
    <div class="label">Total Unique Subdomains</div>
    <div class="value">{len(self.all_subs)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Sources Used</div>
    <div class="value">{len(self.tool_results)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Target Domain</div>
    <div class="value" style="font-size: 1rem; word-break: break-all;">{self.domain}</div>
  </div>
</div>

<h2>Source Breakdown</h2>
<div class="section">
  <table>
    <thead><tr><th>Tool / Source</th><th>Subdomains Found</th></tr></thead>
    <tbody>
{tool_rows}
    </tbody>
  </table>
</div>

<h2>Discovered Subdomains</h2>
<input class="search-box" type="text" id="searchInput"
       placeholder="Filter subdomains..." onkeyup="filterTable()">
<div class="section">
  <table id="subTable">
    <thead>
      <tr>
        <th>#</th>
        <th>Subdomain</th>
        <th>Sources</th>
        <th>Src #</th>
      </tr>
    </thead>
    <tbody>
{sub_rows}
    </tbody>
  </table>
</div>

<footer>
  Generated by
  <a href="https://github.com/DigitalOhara/PerimeterExplorer">PerimeterExplorer</a>
  &mdash; {timestamp}
</footer>

<script>
function filterTable() {{
  const q = document.getElementById("searchInput").value.toLowerCase();
  const rows = document.querySelectorAll("#subTable tbody tr");
  rows.forEach(r => {{
    const sub = r.cells[1] ? r.cells[1].textContent.toLowerCase() : "";
    r.style.display = sub.includes(q) ? "" : "none";
  }});
}}
</script>
</body>
</html>
"""
        path.write_text(html)
        return path

    # ── public entry point ────────────────────────────────────────────────────

    def scan(self) -> dict:
        """Run all tools, write outputs, return paths dict."""
        print()
        info(f"Starting enumeration for: {Fore.CYAN}{self.domain}{Style.RESET_ALL}")
        info(f"Output directory: {self.output_dir}")
        print()

        self.run_all()

        if not self.all_subs:
            warn("No subdomains were found.")
            return {}

        timestamp  = self.output_dir.name.split('_', 1)[-1]   # domain_TIMESTAMP
        base_name  = f"{self.domain}_{timestamp}"

        txt_path  = self.write_txt(base_name)
        csv_path  = self.write_csv(base_name)
        html_path = self.write_html(base_name)

        print()
        success(f"Scan complete — {Fore.GREEN}{len(self.all_subs)}{Style.RESET_ALL} unique subdomains")
        print(f"  {Fore.WHITE}TXT  :{Style.RESET_ALL} {txt_path}")
        print(f"  {Fore.WHITE}CSV  :{Style.RESET_ALL} {csv_path}")
        print(f"  {Fore.WHITE}HTML :{Style.RESET_ALL} {html_path}")

        return {"txt": txt_path, "csv": csv_path, "html": html_path}


# ─── Argument parsing & entry point ───────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="perimeterexplorer",
        description="PerimeterExplorer — Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python perimeterexplorer.py -d example.com
  python perimeterexplorer.py -f domains.txt
  python perimeterexplorer.py -d example.com --vt-key YOUR_VT_API_KEY
  python perimeterexplorer.py -d example.com --wordlist /usr/share/wordlists/subdomains.txt
  python perimeterexplorer.py -d example.com --skip-active
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-d", "--domain",
        help="Single target domain (e.g. example.com)"
    )
    group.add_argument(
        "-f", "--file",
        help="File containing one domain per line"
    )
    parser.add_argument(
        "-o", "--output",
        default="results",
        help="Base output directory (default: ./results)"
    )
    parser.add_argument(
        "--vt-key",
        default=None,
        help="VirusTotal API key (v3). Without it the public UI endpoint is used (limited)."
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Path to wordlist for fierce brute-force (optional)"
    )
    parser.add_argument(
        "--skip-active",
        action="store_true",
        default=False,
        help="Skip active enumeration steps (amass active, fierce)"
    )
    return parser.parse_args()


def load_domains(args) -> list:
    if args.domain:
        return [args.domain.strip()]
    path = Path(args.file)
    if not path.exists():
        error(f"File not found: {args.file}")
        sys.exit(1)
    domains = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith('#')
    ]
    if not domains:
        error("No domains found in file.")
        sys.exit(1)
    return domains


def main():
    print(BANNER)
    args    = parse_args()
    domains = load_domains(args)

    base_output = Path(args.output)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")

    total_found = 0
    for domain in domains:
        out_dir = base_output / f"{domain}_{timestamp}"
        scanner = PerimeterExplorer(
            domain      = domain,
            output_dir  = out_dir,
            vt_api_key  = args.vt_key,
            wordlist    = args.wordlist,
            skip_active = args.skip_active,
        )
        result = scanner.scan()
        total_found += len(scanner.all_subs)
        print()

    if len(domains) > 1:
        print("─" * 50)
        success(f"All domains scanned. Total unique subdomains: {total_found}")


if __name__ == "__main__":
    main()
