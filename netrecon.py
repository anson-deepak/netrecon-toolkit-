#!/usr/bin/env python3
"""
netrecon.py — Network Reconnaissance & Service Fingerprinting CLI

A wrapper around nmap (via python-nmap) for authorized lab/internal network
scanning. Discovers live hosts, open ports, and service/version banners,
optionally maps detected versions to known CVEs, then produces a clean
console report plus JSON/CSV exports.

LEGAL / ETHICAL NOTICE
-----------------------
Only run this against networks and hosts you own or have explicit written
authorization to test (e.g. an isolated lab range, a CTF environment, or
infrastructure covered by a signed pentest engagement). Unauthorized
scanning of third-party networks may be illegal in your jurisdiction.

This tool intentionally does NOT include IDS/IPS evasion, packet
fragmentation, decoy hosts, spoofed source addresses, or other
detection-avoidance techniques. It's meant to be run openly against
networks you control, and it logs exactly what it does.

Requirements
------------
    pip install python-nmap rich
    # nmap binary must also be installed on the host OS:
    #   Debian/Ubuntu: sudo apt install nmap
    #   macOS:         brew install nmap

CVE lookup (--cve)
------------------
    Uses nmap's bundled "vulners" NSE script. It takes the CPE strings that
    service/version detection (-sV) produces and queries the vulners.com API,
    so the machine running the scan needs internet access. Results are based
    on version matching, NOT on actually testing the service, so expect some
    false positives (e.g. distros that backport security fixes without
    changing the version string) and some misses (no version = no CVEs).
    Treat the output as a list of things to investigate, not a verdict.

Usage
-----
    # Basic host discovery + top-1000 TCP port scan with version detection
    python netrecon.py -t 192.168.56.0/24 -o report

    # Same, plus CVE lookup for detected services
    python netrecon.py -t 192.168.56.0/24 --cve -o report

    # Everything: OS detection, all 65535 ports, version detection, CVEs.
    # This is the "get all vulnerabilities, OS, version of every device" mode.
    sudo python netrecon.py -t 192.168.1.0/24 --full -o report

    # Same idea but faster: common ports only, still OS+version+CVE
    sudo python netrecon.py -t 192.168.1.0/24 --full --top-ports 1000 -o report

    # CVE lookup, only keep findings with CVSS >= 7.0
    python netrecon.py -t 192.168.56.10 --cve --min-cvss 7.0 -o report

    # Custom port range, faster timing, skip host discovery (treat all as up)
    python netrecon.py -t 10.0.0.1-50 -p 1-1024 -T4 --no-ping -o scan1

    # SYN scan (faster, requires root/administrator) instead of full connect
    sudo python netrecon.py -t 192.168.1.0/24 --syn -o synscan

    # UDP scan of a few common ports (requires root/administrator)
    sudo python netrecon.py -t 192.168.1.10 --udp -p 53,67,123,161 -o udp_scan

    # Restrict what the tool is even allowed to target
    python netrecon.py -t 192.168.1.0/24 --allow 192.168.1.0/24 -o report

Output
------
    <output>.json   Full structured results incl. CVEs (machine-readable)
    <output>.csv    Flat row-per-service table (spreadsheet-friendly)
    <output>.log    Timestamped log of exactly what was scanned and how
    Console         Rich-formatted summary tables
"""

import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone

try:
    import nmap
except ImportError:
    print("Missing dependency: pip install python-nmap", file=sys.stderr)
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("Missing dependency: pip install rich", file=sys.stderr)
    sys.exit(1)

console = Console()

# Matches vulners output lines such as:
#   "\tCVE-2018-15473\t5.0\thttps://vulners.com/cve/CVE-2018-15473"
CVE_LINE_RE = re.compile(r"^(CVE-\d{4}-\d{4,})\s+(\d+(?:\.\d+)?)(.*)$")


# --------------------------------------------------------------------------
# Environment checks
# --------------------------------------------------------------------------
def check_nmap_installed():
    """Fail fast with a clear message if the nmap binary isn't on PATH,
    instead of letting python-nmap raise an opaque error later."""
    if shutil.which("nmap") is None:
        console.print(
            "[bold red]Error:[/bold red] the 'nmap' binary was not found on your PATH.\n"
            "Install it first:\n"
            "  Debian/Ubuntu/Kali: sudo apt install nmap\n"
            "  macOS:              brew install nmap"
        )
        sys.exit(1)


# --------------------------------------------------------------------------
# Scope enforcement
# --------------------------------------------------------------------------
def _single_target_in_scope(target: str, allowed_networks) -> bool:
    """Check one target token (CIDR, range, or host) against the allow-list."""
    try:
        if "/" in target:
            candidate = ipaddress.ip_network(target, strict=False)
        elif "-" in target:
            # e.g. 10.0.0.1-50 — nmap expands this itself; we conservatively
            # validate just the first host of the range here.
            base = target.split("-")[0]
            candidate = ipaddress.ip_network(base + "/32")
        else:
            candidate = ipaddress.ip_network(target + "/32")
    except ValueError:
        # Hostnames, etc. — can't validate locally; let nmap resolve it and
        # rely on the operator having set --allow correctly.
        return True

    for net in allowed_networks:
        if candidate.version == net.version and candidate.subnet_of(net):
            return True
    return False


def in_allowed_scope(target: str, allowed_networks) -> bool:
    """
    Check whether every target in a (possibly comma-separated) target
    specification falls within the user-supplied --allow networks. If no
    --allow list was given, scope enforcement is skipped (the LEGAL NOTICE
    above still applies).
    """
    if not allowed_networks:
        return True

    targets = [t.strip() for t in target.split(",") if t.strip()]
    return all(_single_target_in_scope(t, allowed_networks) for t in targets)


# --------------------------------------------------------------------------
# Scan execution
# --------------------------------------------------------------------------
def build_nmap_args(args) -> str:
    """Translate CLI flags into an nmap argument string."""
    parts = []

    # Scan type
    if args.udp:
        parts.append("-sU")
    elif args.syn:
        parts.append("-sS")
    else:
        parts.append("-sT")  # full TCP connect, no special privileges needed

    if not args.no_service:
        parts.append("-sV")

    if args.os_detect or args.aggressive or args.full:
        parts.append("-O")

    if args.no_ping:
        parts.append("-Pn")

    # Timing template — default to a moderate T3 rather than an aggressive
    # T4/T5, so the scan doesn't hammer small home-network devices (a lot
    # of consumer routers/IoT gear have thin TCP stacks and choke under
    # aggressive parallel scanning). --full bumps this to T4 by default
    # since it's already scanning every port and would otherwise take a
    # very long time; override with -T if you want it gentler.
    timing = args.timing
    if args.full and args.timing == 3 and "-T" not in (args.scripts or ""):
        timing = 4
    parts.append(f"-T{timing}")

    if args.rate_limit:
        parts.append(f"--max-rate {args.rate_limit}")

    # NSE scripts: user-specified list, or "default" for -A/--full, plus
    # "vulners" when CVE lookup is requested.
    scripts = []
    if args.scripts:
        scripts = [s.strip() for s in args.scripts.split(",") if s.strip()]
    elif args.aggressive or args.full:
        scripts = ["default"]

    if (args.cve or args.full) and "vulners" not in scripts:
        scripts.append("vulners")

    if scripts:
        parts.append(f"--script={','.join(scripts)}")

    min_cvss = args.min_cvss
    if (args.cve or args.full) and min_cvss:
        parts.append(f"--script-args vulners.mincvss={min_cvss}")

    return " ".join(parts)


def resolve_ports(args) -> str:
    """Work out the port spec: explicit -p wins, then --top-ports, then
    --full's 'every port' default, then the plain default."""
    if args.ports != "1-1000":
        return args.ports  # user explicitly overrode it
    if args.top_ports:
        return f"--top-ports-placeholder-{args.top_ports}"  # handled below
    if args.full:
        return "-"  # nmap's "-p-" means all 65535 ports
    return args.ports


def run_scan(target: str, ports: str, top_ports, nmap_args: str, logger: logging.Logger):
    scanner = nmap.PortScanner()

    # --top-ports is a scan-level nmap flag (--top-ports N), not a -p value,
    # so splice it into the argument string instead of the ports field.
    extra_args = nmap_args
    port_kwarg = ports
    if ports.startswith("--top-ports-placeholder-"):
        n = ports.split("-")[-1]
        extra_args = f"--top-ports {n} " + nmap_args
        port_kwarg = None

    logger.info(
        f"Starting scan | target={target} ports={port_kwarg or f'top {top_ports}'} "
        f"args='{extra_args}'"
    )
    start = time.time()

    try:
        if port_kwarg is None:
            scanner.scan(hosts=target, arguments=extra_args)
        else:
            scanner.scan(hosts=target, ports=port_kwarg, arguments=extra_args)
    except nmap.PortScannerError as e:
        logger.error(f"nmap execution failed: {e}")
        console.print(f"[bold red]nmap error:[/bold red] {e}")
        sys.exit(1)

    elapsed = time.time() - start
    logger.info(f"Scan finished in {elapsed:.2f}s")
    return scanner, elapsed


# --------------------------------------------------------------------------
# Result processing
# --------------------------------------------------------------------------
def parse_vulners(output: str):
    """
    Extract CVE entries from the text output of nmap's vulners script.
    Returns a list of dicts sorted by CVSS score (highest first):
        {"id": "CVE-2018-15473", "cvss": 5.0, "exploit_listed": False}
    Non-CVE entries (EDB-ID, PACKETSTORM, etc.) are ignored.
    """
    found = {}
    for raw in (output or "").splitlines():
        m = CVE_LINE_RE.match(raw.strip())
        if not m:
            continue
        cve_id, score, rest = m.group(1), float(m.group(2)), m.group(3)
        entry = found.setdefault(
            cve_id, {"id": cve_id, "cvss": score, "exploit_listed": False}
        )
        entry["cvss"] = max(entry["cvss"], score)
        # vulners flags CVEs that have a public exploit reference
        if "*EXPLOIT*" in rest:
            entry["exploit_listed"] = True
    return sorted(found.values(), key=lambda c: c["cvss"], reverse=True)


def collect_results(scanner: nmap.PortScanner, logger: logging.Logger):
    hosts_scanned = scanner.all_hosts()
    results = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "hosts": [],
    }

    for host in hosts_scanned:
        info = scanner[host]
        state = info.state()

        host_entry = {
            "ip": host,
            "hostname": info.hostname() or None,
            "state": state,
            "os_guess": None,
            "ports": [],
        }

        if state != "up":
            # Host was targeted but didn't respond — log it plainly rather
            # than silently dropping it or retrying to force a response.
            logger.info(f"{host}: no response (state={state})")
            results["hosts"].append(host_entry)
            continue

        if "osmatch" in info and info["osmatch"]:
            best = info["osmatch"][0]
            host_entry["os_guess"] = f"{best['name']} ({best['accuracy']}% confidence)"

        for proto in info.all_protocols():
            for port in sorted(info[proto].keys()):
                pdata = info[proto][port]
                scripts_out = pdata.get("script", {}) or {}
                cves = parse_vulners(scripts_out.get("vulners", ""))

                host_entry["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": pdata.get("state"),
                    "service": pdata.get("name"),
                    "product": pdata.get("product"),
                    "version": pdata.get("version"),
                    "extrainfo": pdata.get("extrainfo"),
                    "cpe": pdata.get("cpe"),
                    "cves": cves,
                })
                if cves:
                    logger.info(
                        f"{host}:{port}/{proto}: {len(cves)} CVE(s), "
                        f"max CVSS {cves[0]['cvss']}"
                    )

        results["hosts"].append(host_entry)
        logger.info(f"{host}: up, {len(host_entry['ports'])} port(s) recorded")

    return results


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def cvss_style(score: float) -> str:
    """Rich color for a CVSS v3-style severity band."""
    if score >= 9.0:
        return "bold red"
    if score >= 7.0:
        return "red"
    if score >= 4.0:
        return "yellow"
    return "green"


def print_console_report(results: dict, elapsed: float, show_cves: bool):
    up_hosts = [h for h in results["hosts"] if h["state"] == "up"]
    down_hosts = [h for h in results["hosts"] if h["state"] != "up"]
    total_cves = len({
        c["id"] for h in up_hosts for p in h["ports"] for c in p.get("cves", [])
    })

    summary = (
        f"Hosts targeted: {len(results['hosts'])}\n"
        f"Hosts up: {len(up_hosts)}\n"
        f"Hosts filtered/no response: {len(down_hosts)}\n"
    )
    if show_cves:
        summary += f"Unique CVEs found: {total_cves}\n"
    summary += f"Elapsed: {elapsed:.2f}s"

    console.print(Panel(summary, title="Scan Summary", border_style="cyan"))

    for host in up_hosts:
        title = host["ip"]
        if host["hostname"]:
            title += f"  ({host['hostname']})"
        if host["os_guess"]:
            console.print(f"[dim]{host['ip']} OS guess: {host['os_guess']}[/dim]")

        table = Table(title=title, show_lines=False)
        table.add_column("Port")
        table.add_column("Proto")
        table.add_column("State")
        table.add_column("Service")
        table.add_column("Product / Version")
        if show_cves:
            table.add_column("CVEs (max CVSS)")

        if not host["ports"]:
            console.print(f"[yellow]{host['ip']}: up, but no open ports found in range[/yellow]")
            continue

        for p in host["ports"]:
            prod_ver = " ".join(filter(None, [p.get("product"), p.get("version")])) or "-"
            row = [
                str(p["port"]), p["protocol"], p["state"] or "-",
                p["service"] or "-", prod_ver,
            ]
            if show_cves:
                cves = p.get("cves", [])
                if cves:
                    top = cves[0]["cvss"]
                    row.append(f"[{cvss_style(top)}]{len(cves)} (max {top})[/]")
                else:
                    row.append("-")
            table.add_row(*row)
        console.print(table)

        # Per-host CVE detail table
        if show_cves:
            detail = Table(title=f"{host['ip']} — CVE details", show_lines=False)
            detail.add_column("Port")
            detail.add_column("CVE")
            detail.add_column("CVSS")
            detail.add_column("Public exploit listed")

            rows = 0
            for p in host["ports"]:
                for c in p.get("cves", []):
                    detail.add_row(
                        f"{p['port']}/{p['protocol']}",
                        c["id"],
                        f"[{cvss_style(c['cvss'])}]{c['cvss']}[/]",
                        "yes" if c["exploit_listed"] else "-",
                    )
                    rows += 1
            if rows:
                console.print(detail)
            else:
                console.print(
                    f"[dim]{host['ip']}: no CVEs returned (service versions may be "
                    f"unidentified, or nothing matched).[/dim]"
                )

    if down_hosts:
        console.print(
            f"[dim]Note: {len(down_hosts)} targeted host(s) did not respond "
            f"(off, filtered, or blocking probes). See log for details.[/dim]"
        )

    if show_cves:
        console.print(
            "[dim]CVE matches are based on version strings and may include false "
            "positives (backported patches) or miss issues. Verify before acting.[/dim]"
        )


def export_json(results: dict, path: str):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)


def export_csv(results: dict, path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ip", "hostname", "state", "os_guess",
            "port", "protocol", "port_state", "service", "product", "version",
            "cpe", "cve_count", "max_cvss", "cves",
        ])
        for host in results["hosts"]:
            if not host["ports"]:
                writer.writerow([
                    host["ip"], host["hostname"] or "", host["state"],
                    host["os_guess"] or "", "", "", "", "", "", "",
                    "", "", "", "",
                ])
                continue
            for p in host["ports"]:
                cves = p.get("cves", [])
                writer.writerow([
                    host["ip"], host["hostname"] or "", host["state"],
                    host["os_guess"] or "",
                    p["port"], p["protocol"], p["state"],
                    p["service"] or "", p["product"] or "", p["version"] or "",
                    p.get("cpe") or "",
                    len(cves),
                    cves[0]["cvss"] if cves else "",
                    ";".join(c["id"] for c in cves),
                ])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Network reconnaissance CLI for authorized/own-network scanning.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-t", "--target", required=True,
                   help="Target: CIDR (192.168.1.0/24), range (10.0.0.1-50), single host, "
                        "or comma-separated list of any of those")
    p.add_argument("-p", "--ports", default="1-1000",
                   help="Port range/list (default: 1-1000). Ignored if --full or "
                        "--top-ports is set and -p wasn't explicitly given.")
    p.add_argument("--top-ports", type=int, default=None,
                   help="Scan nmap's N most common ports instead of a fixed range "
                        "(e.g. --top-ports 1000). Faster than -p- while still covering "
                        "the services most likely to be open.")
    p.add_argument("-o", "--output", default="netrecon_report",
                   help="Output file basename (default: netrecon_report)")

    p.add_argument("--syn", action="store_true",
                   help="Use SYN scan (-sS) instead of full TCP connect. Requires root/admin.")
    p.add_argument("--udp", action="store_true",
                   help="UDP scan (-sU) instead of TCP. Requires root/admin. Slower.")
    p.add_argument("--no-service", action="store_true",
                   help="Skip service/version detection (-sV) for a faster scan")
    p.add_argument("--os-detect", action="store_true",
                   help="Enable OS fingerprinting (-O). Requires root/admin.")
    p.add_argument("-A", "--aggressive", action="store_true",
                   help="Aggressive mode: enables OS detection + version detection "
                        "+ default NSE scripts in one flag (mirrors nmap's -A, minus "
                        "traceroute). Requires root/admin.")
    p.add_argument("--full", action="store_true",
                   help="Comprehensive scan: OS detection + version detection + default "
                        "NSE scripts + CVE lookup (vulners) + every TCP port (1-65535), "
                        "with timing bumped to T4 unless you override -T. This is the "
                        "'everything' preset — expect it to take a while on large "
                        "ranges. Requires root/admin for OS detection. Combine with "
                        "--top-ports to trade thoroughness for speed.")
    p.add_argument("--no-ping", action="store_true",
                   help="Skip host discovery ping, treat all targets as up (-Pn). "
                        "Useful for hosts that block ICMP but are actually online.")
    p.add_argument("-T", "--timing", type=int, default=3, choices=range(0, 6),
                   help="Nmap timing template 0-5 (default: 3, moderate; --full "
                        "defaults to 4 unless you set this explicitly). Lower is "
                        "gentler on fragile home devices.")
    p.add_argument("--rate-limit", type=int, default=None,
                   help="Cap max packets/sec (--max-rate) to avoid overwhelming small devices")
    p.add_argument("--scripts", default=None,
                   help="Comma-separated NSE script categories/names, e.g. 'default,vuln'")

    p.add_argument("--cve", action="store_true",
                   help="Look up known CVEs for detected service versions using nmap's "
                        "'vulners' script. Needs service detection and internet access. "
                        "Implied by --full.")
    p.add_argument("--min-cvss", type=float, default=None,
                   help="With --cve/--full: only report CVEs with CVSS score >= this "
                        "value (0-10)")

    p.add_argument("--allow", action="append", default=None,
                   help="Restrict allowed targets to this CIDR. Repeatable. "
                        "If set, the tool refuses to scan anything outside these ranges.")

    args = p.parse_args()

    if args.full and args.no_service:
        p.error("--full enables service/version detection; it's incompatible with --no-service.")
    if args.top_ports and args.ports != "1-1000":
        p.error("--top-ports and an explicit -p/--ports are mutually exclusive.")

    return args


def setup_logger(output_base: str) -> logging.Logger:
    logger = logging.getLogger("netrecon")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(f"{output_base}.log")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    return logger


def main():
    args = parse_args()
    check_nmap_installed()
    logger = setup_logger(args.output)

    console.print(Panel(
        "[bold]netrecon.py[/bold] — only scan networks/hosts you own or are "
        "explicitly authorized to test.",
        border_style="yellow",
    ))

    if args.cve and args.no_service:
        console.print(
            "[bold red]Error:[/bold red] --cve needs service/version detection; "
            "remove --no-service."
        )
        sys.exit(1)

    if args.min_cvss is not None and not (args.cve or args.full):
        console.print("[yellow]Note: --min-cvss has no effect without --cve or --full.[/yellow]")

    allowed_networks = None
    if args.allow:
        allowed_networks = [ipaddress.ip_network(n, strict=False) for n in args.allow]
        if not in_allowed_scope(args.target, allowed_networks):
            msg = f"Target '{args.target}' is outside the allowed scope: {args.allow}"
            logger.error(msg)
            console.print(f"[bold red]Refusing to scan:[/bold red] {msg}")
            sys.exit(1)

    needs_root = args.syn or args.udp or args.os_detect or args.aggressive or args.full
    if needs_root and os.name != "nt" and os.geteuid() != 0:
        console.print(
            "[yellow]Warning: --syn/--udp/--os-detect/-A/--full typically require root. "
            "Re-run with sudo if the scan fails or OS detection comes back empty.[/yellow]"
        )

    nmap_args = build_nmap_args(args)
    ports = resolve_ports(args)

    try:
        scanner, elapsed = run_scan(args.target, ports, args.top_ports, nmap_args, logger)
        results = collect_results(scanner, logger)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user. Exiting.[/yellow]")
        logger.info("Scan interrupted by user (KeyboardInterrupt)")
        sys.exit(130)

    print_console_report(results, elapsed, show_cves=(args.cve or args.full))

    json_path = f"{args.output}.json"
    csv_path = f"{args.output}.csv"
    export_json(results, json_path)
    export_csv(results, csv_path)

    console.print(f"\n[green]Saved:[/green] {json_path}, {csv_path}, {args.output}.log")


if __name__ == "__main__":
    main()
