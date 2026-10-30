# Network Discovery and Security Assessment Lab

A hands-on lab in the first phase of any security assessment: discovering what is actually on a network, identifying what each host is running, and turning raw scanner output into findings a person can act on. It includes a documented scanning methodology, a Python tool that converts Nmap XML output into a clean assessment report, a sample scan of a virtual lab network, and the written assessment that follows from it.

## Scope and authorization

Every scan in this repository was run against a private virtual lab network (192.168.56.0/24, VirtualBox/VMware host-only) built for this purpose. The rule this lab follows, and the rule that applies professionally: **only scan networks you own or have written authorization to test.** Scanning someone else's network without permission is not a gray area; it can be illegal and it ends careers. The methodology below starts with scope confirmation for that reason.

## Methodology

1. **Confirm scope and authorization.** Written target range, owner, and permission, before a single packet.
2. **Host discovery.** Find which addresses answer: `nmap -sn 192.168.56.0/24`
3. **Port scanning.** Find the open doors on each live host: `nmap -sS -p- <target>` for a full TCP pass in the lab.
4. **Service and version detection.** Learn what is behind each door: `nmap -sV <target>`
5. **Operating system detection.** Best effort fingerprinting: `nmap -O <target>`
6. **Reporting.** Convert the machine readable output into a human findings report, then review it by hand.

The full assessment scan used for the sample data:

```bash
nmap -sV -O -oX sample_scan.xml 192.168.56.0/24
```

The `-oX` flag is the step most beginners skip. The XML output is what makes the scan reusable: it can be parsed, compared against next month's scan, and handed to a tool, which is exactly what the script in this repository does.

## What is in this repository

| File | Purpose |
| --- | --- | --- |
| `parse_nmap_report.py` | Parses Nmap XML output and produces a Markdown assessment report with automatic risk flags. |
| `sample_scan.xml` | Sample Nmap output for the virtual lab network: a domain controller, a workstation, a Linux server, and a printer. |
| `assessment-report.md` | The written assessment of the sample scan: findings, severity reasoning, and recommendations. |
| `LICENSE` | MIT license. |

## How to run the report builder

Python 3, standard library only.

```bash
python parse_nmap_report.py sample_scan.xml
python parse_nmap_report.py scan.xml --out report.md
```

The report contains a host summary table, open ports and service versions per host, and a risk flags section. The flags cover the services an assessor always stops on: Telnet (23), FTP (21), SMB (445), RDP (3389), database ports (1433, 3306), TFTP (69), and VNC (5900), each with the reason it matters.

## What the sample scan shows

- **DC-01 (192.168.56.10)** runs the expected domain controller set: DNS, Kerberos, RPC, LDAP, SMB. The surprise is RDP (3389) reachable on the domain controller, which widens the highest value target on the network.
- **WS-FINANCE-03 (192.168.56.103)** exposes RPC, SMB, and RDP. RDP on a workstation is the classic brute force target, and it matches what happened to this same machine in the [Windows Event Investigation Lab](https://github.com/BGriffith2030/windows-event-investigation-lab).
- **lab-linux-01 (192.168.56.50)** runs SSH and Apache, and one obsolete service: Telnet (23), clear text and unauthenticated by modern standards. That is the lab's top finding.
- **lab-printer (192.168.56.60)** is a reminder that printers are computers: web admin on 80/443 and raw printing on 9100, usually unpatched and forgotten.

The full write-up is in [assessment-report.md](assessment-report.md).

## Skills demonstrated

- Network discovery and enumeration with Nmap: host discovery, SYN scanning, service and OS detection
- TCP/IP fluency: ports, protocols, and what common services mean for risk
- Python for security work: XML parsing and automated report generation (standard library only)
- Assessment writing: separating "open" from "a problem," with the reasoning shown
- Professional scope discipline: authorization first, lab ranges only

## How this maps to the job

Vulnerability analysts and SOC analysts read scans like this constantly: asset inventories, exposure reviews, and the first pass of any incident that starts with "what is on this network?" The deliverable is never the scan. The deliverable is the short list of what matters and what to do about it, which is what the assessment report practices.
