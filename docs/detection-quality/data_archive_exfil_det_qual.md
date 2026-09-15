# Rule #6 — Data Archive for Potential Exfil — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1074 — Data Staged / T1074.001 — Local Data Staging (Collection) |
| **Telemetry** | Sysmon Event ID 11 (File create) — `winlog.event_data.Image`, `winlog.event_data.TargetFilename` |
| **Detection** | Sigma rule matching a `.zip` file created in `\Windows\Temp\` where the creating process is `powershell.exe` |
| **Test** | Converted from a TCM prebuilt Kibana rule; re-validated against this lab's raw `winlog.event_data.*` schema rather than the ECS fields the original assumed |
| **Expected alert** | 1 alert per `.zip` file written to `\Windows\Temp\` by PowerShell |
| **False positives** | Legitimate PowerShell-based backup or packaging scripts writing to Temp (as noted in the rule's own `falsepositives` field) |
| **Severity** | Low |
| **Tuning** | Exclude known backup/deployment script paths or scheduled task names once a baseline of legitimate Temp-zip activity is established; consider correlating with subsequent network activity (a zip immediately followed by an outbound connection is a stronger signal than either alone) |
| **Coverage** | Catches only `.zip` files created **specifically by `powershell.exe`** in **specifically** `\Windows\Temp\`. Does **not** cover: archives created by other processes (cmd.exe, rundll32, a compiled binary, 7-Zip/WinRAR directly), other archive formats (`.7z`, `.rar`, `.tar`), or staging in other common locations (`%APPDATA%`, `%USERPROFILE%\Downloads`, `C:\ProgramData`) |
| **Investigation** | Check the full PowerShell command line (and Script Block Logging/Event 4104 if available, since Sysmon Event ID 11 only shows the file was created, not the command that created it); identify what was archived — check for a preceding pattern of file reads/copies into the same Temp location; check for follow-on network activity or a second process reading the zip |
| **Response** | If confirmed staging for exfil: isolate the host before further outbound activity, preserve the zip for analysis rather than deleting it, and check for how the source files were originally accessed (may point to a broader collection/exfil chain worth investigating upstream) |

**Coverage gap worth noting explicitly:** this rule is narrowly scoped to one process (`powershell.exe`), one extension (`.zip`), and one path (`\Windows\Temp\`). That narrowness was inherited from the original TCM prebuilt rule and wasn't the focus of the conversion work — worth flagging as a known limitation rather than an oversight, and a natural next iteration would broaden the process list (e.g. `cmd.exe`, common archive utilities) and extension list (`.7z`, `.rar`) if this rule needs real-world robustness.

**Note on false positives:** as with the other rules, this hasn't been validated against real production noise — false positives listed are anticipated from technique knowledge, not yet empirically observed.