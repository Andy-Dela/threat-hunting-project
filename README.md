# Threat Hunting Project: PowerShell C2 Detection

## Overview
This project demonstrates a proactive threat hunt conducted on the Splunk BOTS v3 dataset, focused on detecting malicious PowerShell activity, decoding obfuscated commands, and correlating network logs to confirm a command-and-control (C2) compromise.

Rather than waiting for an alert, I began with a hypothesis: **an adversary may be using encoded PowerShell to evade detection.** I searched Windows event logs and network traffic in Splunk and uncovered a Base64-encoded PowerShell command, which I decoded using CyberChef. The decoded script disabled key Windows security controls (AMSI and Script Block Logging) and attempted to communicate with a hardcoded C2 server at `45.77.53.176`.

Pivoting back into Splunk, I confirmed that a host on the network had actually communicated with that IP, establishing the correlation needed to validate the compromise.

## Key Findings

| Indicator | Value |
|-----------|-------|
| Malicious IP | `45.77.53.176` |
| C2 URL | `https://45.77.53.176:443/login/process.php` |
| Attack Type | Encoded PowerShell → C2 Beacon |
| Severity | Critical |
| MITRE ATT&CK | T1059.001, T1071.001, T1562.001 |

## Skills Demonstrated
- **Threat Hunting:** Hypothesis-driven investigation
- **SIEM Analysis:** Splunk (search, stats, table, correlation)
- **Malware Analysis:** Base64 decoding with CyberChef
- **Network Analysis:** C2 beacon identification
- **MITRE ATT&CK Mapping:** Technique identification and documentation
- **Incident Reporting:** Professional investigation write-up

## Tools Used
- **Splunk Enterprise (Free)** — Log analysis and correlation
- **CyberChef** — Base64 decoding and payload analysis
- **MITRE ATT&CK Framework** — Technique mapping

## Project Structure

| File/Folder | Description |
|-------------|-------------|
| [THREAT-HUNT-REPORT.md](threat-hunting-powershell/THREAT-HUNT-REPORT.docx) | Full investigation report |
| [decoded-payload.txt](threat-hunting-powershell/decoded-payload.txt) | The decoded malicious PowerShell script |
| [queries/](threat-hunting-powershell/queries/) | All Splunk queries used during the hunt |
| [screenshots/](threat-hunting-powershell/screenshots/) | Visual evidence captured at each stage |

## Investigation Summary
1. **Hypothesis:** An adversary is using encoded PowerShell to evade detection.
2. **Hunt:** Searched Splunk for PowerShell executions with `-e` and `-enc` flags.
3. **Discovery:** Found a Base64-encoded command on a compromised host.
4. **Analysis:** Decoded the payload in CyberChef — revealed AMSI bypass, Script Block Logging disablement, and a hardcoded C2 server.
5. **Correlation:** Searched Splunk for the malicious IP and confirmed the host communicated with it.
6. **Conclusion:** Active C2 beacon confirmed. Severity: Critical.

## About This Project
This project was built to demonstrate hands-on threat hunting skills, including the ability to:
- Hunt for threats without relying on alerts
- Analyze malicious scripts
- Correlate network activity with endpoint logs
- Document findings in a clear, professional format

---
