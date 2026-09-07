# Rule #11 — SMB Admin Share Access via net.exe — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1021.002 — Remote Services: SMB/Windows Admin Shares (Lateral Movement) |
| **Telemetry** | Sysmon Event ID 1 (process creation) — `winlog.event_data.Image`, `winlog.event_data.CommandLine`; correlated with Windows Security Event ID 4624 (LogonType 3) — `winlog.event_data.TargetUserName` |
| **Detection** | Sigma rule matching `net.exe`/`net1.exe` process creation where the command line references `C$`, `ADMIN$`, or `IPC$` |
| **Test** | Atomic Red Team, T1021.002 test #1 (Map admin share), executed against `localhost\C$` on the Win11 lab VM |
| **Expected alert** | 1 alert per admin-share connection attempt via `net use` |
| **False positives** | Legitimate IT/backup scripts, software deployment tools (SCCM, PDQ Deploy), or admins manually connecting to admin shares for routine maintenance. *(Anticipated based on technique research — not yet observed against real production traffic; this lab test only validated true-positive detection.)* |
| **Severity** | Medium |
| **Tuning** | Exclude known backup/deployment service accounts and approved admin hosts once identified in production; consider raising severity when combined with the `/u:` explicit-credentials switch, which is less common in routine automated scripts |
| **Coverage** | Catches command-line-driven `net use`/PsExec-style SMB admin-share connections. Does **not** cover: PowerShell-native SMB access (e.g. `New-PSDrive`, `New-SmbMapping`) without a `net.exe` call, or WMI/WinRM-based lateral movement (separate technique, T1021.006) |
| **Investigation** | Confirm source/destination host pairing; check whether the account normally has legitimate reason to reach that host; correlate with the 4624 LogonType 3 event to confirm authentication succeeded (vs. a failed/rejected attempt); check for follow-on activity (file writes to the share, service creation — PsExec pattern) |
| **Response** | If unauthorized: disable the account, isolate the source host, and review for lateral spread to the target host; if a known admin/service account acting outside its normal pattern, verify with the owning team before escalating |