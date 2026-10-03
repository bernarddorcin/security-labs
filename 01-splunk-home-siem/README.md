# Lab 01: Splunk Home SIEM

**Goal:** collect Windows Security, Sysmon and Linux auth logs into Splunk, simulate four common attacker techniques, and detect each one with a scheduled alert and a triage dashboard.

## Architecture

```
Windows Server 2025 VM (Sysmon + audit policy) ── Universal Forwarder ──┐
Ubuntu Server 24.04 (/var/log/auth.log, sshd)  ── Universal Forwarder ──┤ TCP 9997
                                                                         └─> Splunk Enterprise (Windows 11 host)
                                                                               ├─ index=wineventlog  (Security log, XML)
                                                                               ├─ index=sysmon       (Sysmon Operational, XML)
                                                                               ├─ index=linux        (auth.log, linux_secure)
                                                                               ├─ Windows, Sysmon, Unix/Linux add-ons
                                                                               └─ Alerts LC-001..004 + "Lab Corp SOC Triage" dashboard
```

## Setup summary

| Component | Configuration |
| --- | --- |
| Hypervisor | VMware Workstation, both VMs on an isolated NAT network (VMnet8) with static IPs |
| SIEM | Splunk Enterprise on the Windows 11 host, receiving on 9997, indexes `wineventlog`, `sysmon`, `linux` |
| Linux source | Ubuntu with sshd; Universal Forwarder monitors `/var/log/auth.log` |
| Endpoint | Windows Server 2025, Sysmon with the SwiftOnSecurity config, audit policy: Logon, User Account Management, Security Group Management (success + failure) |
| Forwarder | Universal Forwarder, `inputs.conf` below |

```ini
[WinEventLog://Security]
disabled = 0
index = wineventlog
renderXml = true

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
```

## Detections

| ID | What it catches | Logic | Data |
| --- | --- | --- | --- |
| LC-001 | Brute force and password spray | ≥10 failed logons, or ≥5 distinct users, from one source in 10 minutes | Security 4625 |
| LC-002 | Encoded / download-cradle PowerShell | powershell.exe or pwsh.exe with `-enc`, `DownloadString` or `IEX` | Sysmon 1 |
| LC-003 | New local admin | Account created (4720) or added to local Administrators (4732) | Security 4720, 4732 |
| LC-004 | SSH brute force (Linux) | ≥10 `Failed password` lines, or ≥5 users, from one source in 10 minutes; fields extracted with `rex` | auth.log |

Each detection runs every 10 minutes over the last 10 minutes, adds to Triggered Alerts, and throttles for 60 minutes per source or host.

## How I tested it

| Detection | Simulation (safe, lab only) |
| --- | --- |
| LC-001 | 12 bad passwords for one non-existent account, then one password against 6 non-existent accounts (`net use \\127.0.0.1\IPC$`) |
| LC-002 | `powershell -EncodedCommand` that only prints "Lab Corp detection test" |
| LC-003 | `net user labadmin2 ... /add` then `net localgroup Administrators labadmin2 /add` (account deleted afterwards) |
| LC-004 | 12 bad SSH passwords for a non-existent user with `sshpass` against the Ubuntu VM |

## Results

_To be added with screenshots: what fired, how fast, and what the alert looked like._

## Triage notes (how I'd work each alert)

- **LC-001:** confirm the count and source; check for a 4624 success from the same source after the failures (that raises severity); scope other accounts targeted; block the source and reset the account if anything succeeded.
- **LC-002:** decode the base64 payload; check the parent process and user; look for network connections (Sysmon 3) and file writes (Sysmon 11) from the same process; isolate the host if the payload downloads or executes anything.
- **LC-003:** who made the change (SubjectUserName) and was it approved (change ticket)? If not, disable the account, remove it from Administrators, and hunt for what the creator did before and after.
- **LC-004:** check for an `Accepted password`/`Accepted publickey` from the same source afterwards; if none, block the source (ufw/fail2ban) and confirm password login is needed at all; if one, treat the account as compromised.

## What I'd tune

_To be added: false positives seen and the allow-list or threshold change made._

## Screenshots

See [screenshots/](screenshots/).
