NetRecon --- Network Reconnaissance & Service Fingerprinting
NetRecon is a Python command-line tool that wraps Nmap to inventory
devices on an authorized network, identify open ports and exposed
services, fingerprint service versions and operating systems where
possible, and optionally look up potential CVEs. It displays a terminal
summary and exports JSON, CSV, and log reports.
Authorization: Scan only networks and devices you own or have
explicit permission to assess. Scanning can trigger security alerts or
disrupt fragile devices. Start with a small, approved scope.

Features
- Scan a single host, CIDR subnet, IP range, or comma-separated
  targets.
- Enumerate TCP or UDP ports and identify responding hosts.
- Detect service names, products, versions, extra information, and
  CPEs when Nmap can identify them.
- Attempt OS fingerprinting (best results generally require
  administrator/root privileges).
- Optionally query Nmap's vulners script for CVE matches based on
  detected service/version information.
- Filter CVE results by minimum CVSS score.
- Restrict targets using the repeatable --allow CIDR allow-list.
- Export JSON, CSV, and timestamped log files.
Important: No scanner can guarantee it will identify every device,
OS, version, or vulnerability. Firewalls, VLAN boundaries, offline
devices, filtered ports, unidentifiable banners, and authenticated-only
checks can limit results. CVE matches are leads to verify, not proof
that a device is vulnerable.
Requirements
- Python 3
- Nmap installed and available on PATH
- Python packages: python-nmap and rich
- Internet access for the vulners CVE lookup
Install on Kali Linux / Debian / Ubuntu
sudo apt update
sudo apt install nmap python3-pip
python3 -m pip install python-nmap rich
If your system manages Python packages externally, use a virtual
environment:
python3 -m venv .venv
source .venv/bin/activate
pip install python-nmap rich
Quick start
Find your subnet:
ip route
Replace the example subnet below with the actual network range you are
authorized to scan:
sudo python3 netrecon.py -t 192.168.1.0/24 --allow 192.168.1.0/24 --full -o network_report
If your script is named netrecon_fixed.py, use that filename instead.
The --full preset enables OS detection, service/version detection,
default Nmap NSE scripts, the vulners CVE lookup, and all TCP ports
unless --top-ports is supplied. It can take considerable time on a
subnet.
Usage examples
Basic scan (default TCP ports 1--1000):
python3 netrecon.py -t 192.168.1.10 -o basic_report
Service/version scan with CVE lookup:
python3 netrecon.py -t 192.168.1.0/24 --cve -o cve_report
Comprehensive TCP scan:
sudo python3 netrecon.py -t 192.168.1.0/24 --allow 192.168.1.0/24 --full -o full_report
Faster scan of the 1,000 most common ports:
sudo python3 netrecon.py -t 192.168.1.0/24 --allow 192.168.1.0/24 --full --top-ports 1000 -o common_ports
Report CVE matches with CVSS 7.0 and above:
python3 netrecon.py -t 192.168.1.10 --cve --min-cvss 7.0 -o high_cvss
Custom TCP port range:
python3 netrecon.py -t 192.168.1.10 -p 1-1024 -o custom_ports
UDP scan of selected common ports (typically requires root/admin):
sudo python3 netrecon.py -t 192.168.1.10 --udp -p 53,67,123,161 -o udp_report
Skip host discovery probes for a host that may block them:
sudo python3 netrecon.py -t 192.168.1.10 --no-ping --os-detect -o no_ping_report
--no-ping treats targets as up for scanning; it does not guarantee
their services will respond.
Command-line options
  Option                              Description
  -t, --target                    Required target: IP, CIDR, range,
                                      or comma-separated target list.

  -p, --ports                     Port range/list. Default 1-1000;
                                      --full scans all TCP ports unless
                                      overridden by --top-ports.

  --top-ports N                     Scan N of Nmap's most common ports
                                      instead of a fixed range.

  -o, --output                    Output filename basename. Default:
                                      netrecon_report.

  --syn                             Use a SYN scan; usually requires
                                      root/admin privileges.

  --udp                             Use UDP scanning; usually requires
                                      root/admin privileges and can be
                                      slow.

  --no-service                      Skip service/version detection.
                                      Incompatible with --full.

  --os-detect                       Attempt OS fingerprinting.

  -A, --aggressive                Enable OS detection, version
                                      detection, and default NSE scripts.

  --full                            OS detection, version detection,
                                      default NSE scripts, CVE lookup,
                                      and all TCP ports by default.

  --no-ping                         Skip host discovery probes and
                                      treat targets as up.

  -T, --timing                    Nmap timing template from 0 to 5.
                                      Default 3; --full defaults to 4
                                      unless overridden.

  --rate-limit N                    Set Nmap's maximum packet rate.

  --scripts LIST                    Comma-separated Nmap NSE
                                      scripts/categories. Use scripts
                                      suitable for your authorized
                                      assessment.

  --cve                             Use the vulners script to look up
                                      potential CVEs for detected
                                      versions.

  --min-cvss SCORE                  Set a minimum CVSS score for the
                                      vulners query.

  --allow CIDR                      Restrict targets to an allowed
                                      CIDR; repeat for additional
                                  authorized ranges.
Run python3 netrecon.py --help for the options supported by your
installed version.
Output files
For -o network_report, NetRecon creates:
- network_report.json --- structured host, port, service, and CVE
  results.
- network_report.csv --- one row per recorded service/port, suitable
  for spreadsheet analysis.
- network_report.log --- timestamped execution log.
The terminal also displays a summary. Protect reports because they can
reveal network structure, software versions, and security weaknesses.
Understanding results
- Host state: Nmap's assessment of whether a host responded.
- Port state: A port may be open, closed, filtered, or otherwise
  classified.
- Product/version: Details Nmap inferred from service
  fingerprinting. Missing version data does not mean a service is
  safe.
- OS guess: A fingerprint-based estimate, not a guaranteed
  identification.
- CVE/CVSS: Potential vulnerability matches and their reported
  severity. Verify affected versions, vendor advisories, distribution
  backports, and configuration before treating a match as confirmed.
- No CVEs returned: This does not prove the service is free of
  vulnerabilities.
Recommended workflow
1. Define and document the authorized IP range.
2. Start with a limited scan to confirm scope and setup.
3. Run --full when a comprehensive TCP port inventory is appropriate.
4. Run a separate UDP scan for relevant UDP services; an all-TCP scan
   does not cover UDP.
5. Review the JSON/CSV output and validate important findings against
   vendor advisories or an authenticated vulnerability scanner.
6. Remediate confirmed issues and rescan to verify the fix.
Troubleshooting
- nmap not found: Install Nmap and confirm nmap --version
  works in the same terminal.
- Missing Python modules: Install python-nmap and rich in the
  Python environment used to run the script.
- No OS guess: Run with appropriate privileges and ensure the
  target returns enough fingerprinting responses.
- No host found: Check the subnet, routing, VLAN, firewall rules,
  and discovery filtering. Use --no-ping only when appropriate.
- No version/CVE results: Some services hide banners; CVE lookup
  depends on version/CPE data and internet access.
- Long scan time: Full TCP scans across many hosts can take a
  while. Use --top-ports 1000 for an initial inventory.
- Unexpected CVE matches: Version-based lookup can produce false
  positives, especially when vendors backport security fixes. Verify
  each finding.
Responsible use
Use only with authorization. Choose appropriate scan rates, schedule
sensitive scans carefully, protect generated reports, and verify
findings before remediation.
License
No license is specified. Add a license file if you intend to distribute
the project.
