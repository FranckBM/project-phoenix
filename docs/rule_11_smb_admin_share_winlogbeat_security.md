Rule #11 Added — SMB Admin Share Access + Winlogbeat Security Gap
Summary

Added the 11th Sigma rule (T1021.002 — Lateral Movement) using Atomic Red Team as the telemetry source instead of HTB, given the decision this session to skip HTB Labs VIP+ (Academy-only membership) to keep costs low during a house move. Also surfaced and fixed a second Winlogbeat pipeline gap — the Security event log channel was never being collected, meaning Event ID 4624 was invisible the whole time despite Sysmon telemetry working fine.

Building and validating rule #11

Technique: T1021.002 (SMB/Windows Admin Shares), triggered via Invoke-AtomicTest T1021.002 -TestNumbers 1 (Map admin share) against localhost\C$ on the Win11 lab VM — no second host available, so looped back against itself rather than standing up Samba on the Parrot box.

Blockers hit before getting clean telemetry:

Atomic's default computer_name input is the literal placeholder "Target", not a real host — needed explicit -InputArgs to point at localhost.
Forgot the local admin password mid-session → locked out of the VM → recovered via VirtualBox snapshot revert → reset password properly this time.
net use \\localhost\C$ still failed after the password fix — Windows applies UAC Remote Restriction to local (non-domain) admin accounts over the network, stripping the elevated token even with correct credentials. Fixed via:
powershell
  New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force

Second pipeline gap found: confirmed via Get-WinEvent -LogName Security that Event ID 4624 was generating locally on the VM, but never appearing in Elastic — Winlogbeat's event_logs config never included the Security channel at all (only Sysmon had been configured). Fixed in winlogbeat.yml:

yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4104
  - name: Security

Confirmed the fix via the Winlogbeat log file itself — the periodic metrics snapshot began showing a "Security" dataset with received_events_total climbing, right after Restart-Service winlogbeat.

Also briefly queried the wrong Kibana data view (.kibana-event-log-*, Kibana's own internal log — not Windows telemetry at all) before catching it and switching to "Security solution default." Worth remembering to check the Data View dropdown before assuming a query is broken.

Confirmed in Elastic, once the pipeline was fixed and the test re-run:

Process creation: net.exe, CommandLine: net use \\localhost\C$ ... /u:WIN11-REBUILD\vboxuser
Parent chain: PowerShell → cmd.exe → cmd.exe → net.exe (double-hop is an Atomic Red Team harness artifact, not representative of a real attack chain — noted so the Sigma rule doesn't overfit to it)
Event 4624, LogonType 3, TargetUserName vboxuser — confirming the actual network authentication, distinct from routine Type 5 (Service) 4624 noise also present in the index
Sigma rule
yaml
title: SMB Admin Share Access via net.exe
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains:
      - '\C$'
      - '\ADMIN$'
      - '\IPC$'
  condition: selection
level: medium

Validated syntax with sigma convert -t lucene --without-pipeline, then manually translated per field-mapping-notes.md (Image → winlog.event_data.Image, CommandLine → winlog.event_data.CommandLine) and confirmed the translated query matched captured telemetry in Discover before import.

Kibana import

Imported via Kibana UI directly (Custom query/KQL rule type) rather than sigma convert -t eql, since the ECS pipeline gap documented for this lab means the EQL converter's output wouldn't match raw schema anyway. MITRE mapping: Lateral Movement (TA0008) → Remote Services (T1021) → SMB/Windows Admin Shares (T1021.002). Severity: Medium, risk score 47.

Result: rule enabled, ran on schedule, fired a real alert (SMB Admin Share Access via net.exe) against the atomic test event. Confirmed in the Alerts table with correct rule name, severity, and risk score.

Rule coverage status update
#	Rule	Technique	Status
11	SMB Admin Share Access via net.exe (new this session)	T1021.002	✅ (imported to Kibana via UI, alert confirmed firing)

(1–10 unchanged from prior sessions — all ✅)