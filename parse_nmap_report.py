#!/usr/bin/env python3
"""
Nmap XML Report Builder
-----------------------
Reads an Nmap XML output file (created with: nmap -sV -O -oX scan.xml ...)
and turns it into a clean Markdown assessment report:

  * A summary table of every live host (address, hostname, OS guess)
  * The open ports and service versions for each host
  * Automatic risk flags for services that deserve a second look

Usage:
    python parse_nmap_report.py sample_scan.xml
    python parse_nmap_report.py scan.xml --out report.md

Only the Python standard library is used.
"""

import argparse
import sys
import xml.etree.ElementTree as ET

# Ports and services that an assessor always stops on. The note explains WHY,
# because a flag without a reason teaches nothing.
RISK_NOTES = {
    21: "FTP sends credentials in clear text. Confirm it is needed; prefer SFTP.",
    23: "Telnet is clear text and obsolete. Treat as a finding until removed.",
    69: "TFTP has no authentication. Confirm it is restricted to a trusted segment.",
    445: "SMB is a high value target (EternalBlue history). Confirm patching and restrict exposure.",
    1433: "Microsoft SQL Server. Confirm it is not reachable beyond application servers.",
    3306: "MySQL. Confirm it is not reachable beyond application servers.",
    3389: "RDP is the most common brute force and ransomware entry point. Confirm MFA, lockout, and restricted source ranges.",
    5900: "VNC remote access. Confirm strong authentication and restricted sources.",
}


def host_address(host):
    """Return the IPv4 address of a host element."""
    for addr in host.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr")
    return "unknown"


def host_name(host):
    """Return the first hostname, or a dash when Nmap found none."""
    hostnames = host.find("hostnames")
    if hostnames is not None:
        element = hostnames.find("hostname")
        if element is not None:
            return element.get("name")
    return "-"


def host_os(host):
    """Return the best OS guess (highest accuracy), or 'unknown'."""
    os_element = host.find("os")
    if os_element is not None:
        matches = os_element.findall("osmatch")
        if matches:
            best = max(matches, key=lambda m: int(m.get("accuracy", 0)))
            return best.get("name")
    return "unknown"


def open_ports(host):
    """Return a list of (port, protocol, service, version) for open ports."""
    results = []
    ports = host.find("ports")
    if ports is None:
        return results
    for port in ports.findall("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        name = service.get("name") if service is not None else "-"
        product = service.get("product", "") if service is not None else ""
        version = service.get("version", "") if service is not None else ""
        extrainfo = service.get("extrainfo", "") if service is not None else ""
        version_text = " ".join(x for x in [product, version, extrainfo] if x).strip()
        results.append(
            (int(port.get("portid")), port.get("protocol"), name, version_text or "-")
        )
    return sorted(results)


def build_report(root):
    """Turn the parsed XML tree into a Markdown report string."""
    lines = []
    scan_info = root.find("scaninfo")
    command = root.get("args", "nmap scan")
    lines.append("# Network Assessment Report")
    lines.append("")
    lines.append(f"Source scan: `{command}`")
    lines.append("")

    hosts = [h for h in root.findall("host") if h.find("status") is not None
             and h.find("status").get("state") == "up"]
    lines.append(f"Live hosts found: **{len(hosts)}**")
    lines.append("")

    lines.append("## Host summary")
    lines.append("")
    lines.append("| Address | Hostname | OS (best guess) | Open ports |")
    lines.append("| --- | --- | --- | --- |")
    per_host = []
    for host in hosts:
        ports = open_ports(host)
        per_host.append((host, ports))
        lines.append(
            f"| {host_address(host)} | {host_name(host)} | {host_os(host)} | {len(ports)} |"
        )
    lines.append("")

    lines.append("## Detail by host")
    for host, ports in per_host:
        lines.append("")
        lines.append(f"### {host_address(host)} ({host_name(host)})")
        lines.append("")
        if not ports:
            lines.append("No open ports found.")
            continue
        lines.append("| Port | Protocol | Service | Version |")
        lines.append("| --- | --- | --- | --- |")
        for portid, protocol, name, version_text in ports:
            lines.append(f"| {portid} | {protocol} | {name} | {version_text} |")
    lines.append("")

    lines.append("## Risk flags")
    lines.append("")
    flags = []
    for host, ports in per_host:
        for portid, protocol, name, version_text in ports:
            if portid in RISK_NOTES:
                flags.append(
                    f"- **{host_address(host)} port {portid} ({name}):** {RISK_NOTES[portid]}"
                )
    if flags:
        lines.extend(flags)
    else:
        lines.append("No automatically flagged services. Manual review still required.")
    lines.append("")
    lines.append("Generated by parse_nmap_report.py from Nmap XML output.")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Turn an Nmap XML file into a Markdown assessment report."
    )
    parser.add_argument("xml_file", help="Path to the Nmap XML output file")
    parser.add_argument("--out", help="Optional file path to save the report")
    args = parser.parse_args()

    try:
        tree = ET.parse(args.xml_file)
    except FileNotFoundError:
        sys.exit(f"File not found: {args.xml_file}")
    except ET.ParseError as error:
        sys.exit(f"Could not parse {args.xml_file}: {error}")

    report = build_report(tree.getroot())
    print(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(report)
        print(f"Report saved to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
