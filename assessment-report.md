# Assessment Report: Virtual Lab Network 192.168.56.0/24

**Assessor:** Brandon Griffith
**Scan date:** October 12, 2026
**Scope:** 192.168.56.0/24, virtual lab network (owned lab environment, authorization: self, lab owner)
**Method:** Nmap host discovery, SYN scan, service and OS detection (`nmap -sV -O -oX`)
**Tooling:** parse_nmap_report.py (this repository) plus manual review

## Summary

Four live hosts were found: a Windows Server 2022 domain controller, a Windows 11 finance workstation, an Ubuntu Linux server, and a network printer. No unknown or rogue devices appeared. The exposure is mostly expected for a lab, with three findings worth fixing and one obsolete service that should be removed outright.

## Findings

### Finding 1: Telnet enabled on lab-linux-01 (192.168.56.50, port 23) — High for a production network

Telnet sends everything, including credentials, in clear text, and it has no place on a modern network when SSH (port 22, already running on the same host) does the same job encrypted. In this lab it is a deliberate teaching example; on a real network this is a fix-first item.

**Recommendation:** Disable and remove the Telnet service; confirm SSH is the only remote shell path.

### Finding 2: RDP reachable on the domain controller and the finance workstation (3389) — Medium

RDP is the most common brute force and ransomware entry point in Windows environments. On DC-01 it is exposed on the network's highest value target. On WS-FINANCE-03 it is exactly the door that the brute force attack in the companion investigation used (logon type 10).

**Recommendation:** Restrict RDP by firewall rule to an admin jump host, require MFA, and set account lockout. On the domain controller, remove RDP entirely if it is not part of the admin workflow.

### Finding 3: SMB exposed on both Windows hosts (445) — Medium, informational in a lab

SMB is required for domain operations, so this is not a misconfiguration. It is flagged because SMB's history (EternalBlue, wormable ransomware spread) makes patch level and exposure scope a standing check, not a one time one.

**Recommendation:** Keep SMB limited to the internal segment, verify patching monthly, and disable SMBv1 everywhere.

### Finding 4: Printer services unmanaged (192.168.56.60, ports 80, 443, 9100) — Low

The printer's web administration and raw print service are reachable from the whole segment. Printers rarely receive firmware updates and often keep default credentials, which makes them quiet footholds.

**Recommendation:** Change the admin password from default, update firmware, and place printers on their own segment where practical.

## What was checked and found normal

- No unexpected hosts answered the discovery scan; the inventory matches the lab design.
- No database services (1433, 3306) are exposed on any host.
- No FTP, TFTP, or VNC services were found.
- SSH on lab-linux-01 is a current OpenSSH build for its Ubuntu release.

## Assessor note

An open port is not automatically a vulnerability. Kerberos and LDAP open on a domain controller is the design. The assessor's work is the judgment layer on top of the scan: which of these openings are expected, which are risky in context, and which are simply wrong. Telnet is wrong. RDP on the domain controller is risky in context. Everything else here is expected, and the report says so, because a findings list that cries wolf on normal services gets ignored when it matters.
