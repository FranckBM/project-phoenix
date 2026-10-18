# Rule #11 — SMB Admin Share Access via net.exe — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1021.002 — Remote Services: SMB/Windows Admin Shares (Lateral Movement) |
| **Telemetry** | Sysmon Event ID 1 (process creation) — `winlog.event_data.Image`, `winlog.event_data.CommandLine`; correlated with Windows Security Event ID 4624 (LogonType 3) — `winlog.event_data.TargetUserName` |
| **Detection** | Sigma rule matching `net.exe`/`net1.exe` process creation where the command line references `C$`, `ADMIN$`, or `IPC$` |
| **Test** | Atomic Red Team, T1021.002 test #1 (Map admin share), executed against `localhost\C$` on the Win11 lab VM |
| **Expected alert** | 1 alert per distinct host and command line per hour. Repeats of the same command within the hour are suppressed and counted on the alert (see Alert suppression below) |
| **False positives** | Legitimate IT/backup scripts, software deployment tools (SCCM, PDQ Deploy), or admins manually connecting to admin shares for routine maintenance. *(Anticipated based on technique research — not yet observed against real production traffic; this lab test only validated true-positive detection.)* |
| **Severity** | Medium |
| **Tuning** | Exclude known backup/deployment service accounts and approved admin hosts once identified in production; consider raising severity when combined with the `/u:` explicit-credentials switch, which is less common in routine automated scripts |
| **Coverage** | Catches command-line-driven `net use`/PsExec-style SMB admin-share connections. Does **not** cover: PowerShell-native SMB access (e.g. `New-PSDrive`, `New-SmbMapping`) without a `net.exe` call, or WMI/WinRM-based lateral movement (separate technique, T1021.006) |
| **Investigation** | Confirm source/destination host pairing; check whether the account normally has legitimate reason to reach that host; correlate with the 4624 LogonType 3 event to confirm authentication succeeded (vs. a failed/rejected attempt); check for follow-on activity (file writes to the share, service creation — PsExec pattern) |
| **Response** | If unauthorized: disable the account, isolate the source host, and review for lateral spread to the target host; if a known admin/service account acting outside its normal pattern, verify with the owning team before escalating |

## Alert suppression (added 2026-10-18)

**Problem:** rule #11 (SMB Admin Share Access via net.exe) was imported without alert suppression. Repeated test runs of the same command produced pages of near-identical alerts for one activity.

**Change:** alert suppression was added to the live Kibana rule.

| Setting | Value |
|---|---|
| Suppress alerts by | `host.name` and `winlog.event_data.CommandLine` |
| Suppress alerts for | 1 hour, per time period |
| If a suppression field is missing | do not suppress alerts for events with missing fields |
| Additional look-back | 10 minutes (was 5), same as the AWS rules |

Suppressing on the command line, not just the host, means repeats of the same command on the same machine collapse into one alert, while a different share or target from the same machine still alerts on its own.

**Test (Windows lab VM, 2026-10-18):**

1. `net use \\localhost\C$` at 11:10:19.
2. The same command again at 11:11:48.
3. `net use \\localhost\ADMIN$`, a different share.

All three events were confirmed in `winlogbeat-*` before the alerts were checked.

**Result:** 3 matching events produced 2 alerts, not 3.

- The alert for the repeated `C$` command (created 11:13:05) has `kibana.alert.suppression.docs_count` 1, with a suppression window from 11:10:19 to 11:11:48, matching the two `C$` events. Its `CommandLine` is `"C:\WINDOWS\system32\net.exe" use \\localhost\C$`.
- The `ADMIN$` command alerted separately (created 11:18:05), with `CommandLine` `"C:\WINDOWS\system32\net.exe" use \\localhost\ADMIN$` and `docs_count` 0. A different share from the same host was not folded into the first alert.

**Not tested / limits:**

- Detection latency (command run to alert) was not captured for this test, so no new figure is claimed here.
- Suppression hides repeat alerts for an hour, but the suppressed count stays visible on the alert, so a burst of repeats is not lost.
- False positive rate and alert volume remain unmeasured. They are blocked on real traffic, and no figures are claimed.