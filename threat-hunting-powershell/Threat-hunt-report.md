# Threat Hunting Report: PowerShell C2 Detection


A threat hunt is when an analyst goes looking for threats instead of waiting for an alert to go off. I used Splunk for this one, it's a SIEM tool that pulls logs together so you can spot behavior that doesn't match the normal baseline. My plan was simple: start with a hypothesis, collect the data, run the queries, confirm or kill the hypothesis, then write it up and escalate if it's real.

**Hypothesis:** An attacker is using PowerShell to hide their tracks and talk to a command server. I pulled Windows Event logs and network logs to test it.

---

## Finding the Encoded Command

I searched Splunk for PowerShell activity using the encoding flags attackers rely on to hide what they're running:
index=* powershell.exe "-e" OR "-enc" | table _time, host, user, CommandLine

<img width="2880" height="1632" alt="encoded powershell" src="https://github.com/user-attachments/assets/924a65a7-de05-4ff9-a1aa-823097d9a8b8" />

That gave me a Base64-encoded command line. Attackers encode PowerShell like this specifically so the payload doesn't sit in plain text where anyone glancing at the logs could read it.
I dropped the string into CyberChef and decoded it from Base64.

<img width="2880" height="1864" alt="decoded base64" src="https://github.com/user-attachments/assets/0678856a-c634-4a42-bf29-c2611fc17707" />

Once it was readable, a few things jumped out immediately, and each one told me something different about what this script was built to do.
It starts by setting EnableScriptBlockLogging and EnableScriptBlockInvocationLogging to 0, which just switches off PowerShell's own logging so none of this gets recorded. That's defense evasion, MITRE TA0030. Then it goes after AMSI, Windows' built-in antimalware scanner, by forcing amsiInitFailed to $true. Basically tricking AMSI into thinking it never loaded properly, so it never gets a chance to flag anything. After that there's a line pulling data down from somewhere else ($wc.DownloadData), and right before it, the script disables certificate validation entirely by hardcoding the callback to $true, so it'll happily talk to a server with a fake or invalid cert. And then IEX at the end, which is the payoff: download, decrypt, execute, all in memory.
Put that all together and there's no ambiguity. This is malicious.
#### PowerShell → Obfuscation → Disable logging → Bypass AMSI → Disable cert validation → Contact remote server → Download data → Decrypt payload → IEX → Execute
---


## Tracking Down the C2 Server

Hypothesis confirmed. Now I needed to know where this thing was actually calling home.

Buried in the decoded script was another Base64 string, this time hiding the destination address:

```powershell
$ser = $([Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String(
        'aAB0AHQAcABzADoALwAvADQANQAuADcANwAuADUAMwAuADEANwA2ADoANAA0ADMA'
    )
))
```
<img width="1440" height="816" alt="host" src="https://github.com/user-attachments/assets/018f7b33-2d73-4c80-86a2-c604eb955ba3" />

The host Wright.local had outbound connections to that IP. So this wasn't just a script sitting on disk waiting to run, it had already phoned home.

---
**Compromised host:** Wright.local **C2 server:** 45.77.53.176, port 443 **How it got in:** an encoded PowerShell command (MITRE T1059.001) that disabled logging, bypassed AMSI, and reached out to a remote server over the web (MITRE T1071.001), with the logging shutdown itself mapping to T1562.001.

#### What should happen next

Wright.local needs to be contained, that connection to the C2 server is live, not theoretical. Block 45.77.53.176 at the firewall and proxy so nothing on the network can reach it even by accident. Reset credentials for anything that logged into that host recently, since we don't know yet what else the attacker touched. Turn Script Block Logging and AMSI back on everywhere, not just on this machine, because whoever built this script clearly knew both were worth disabling. And don't stop at one host, run this same IOC set across the rest of the environment, because a beacon this deliberate rarely targets just one machine.

#### What this taught me
Encoded PowerShell doesn't trip alerts on its own, you have to go looking for it. And decoding the script only tells half the story, it's pairing that with the network logs that actually proves someone's phoning home. I also learned that disabled logging can quietly strip out fields like user and dest_ip, so a clean-looking query result doesn't always mean a clean host, sometimes you have to go check the raw logs yourself.
**Severity: Critical.**



