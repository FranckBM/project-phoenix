# Rule #10 — Suspicious File Written to Temp Directory — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1082 — System Information Discovery / T1217 — Browser Information Discovery *(as tagged)* — though logic-wise this rule sits closer to T1105 (Ingress Tool Transfer) or T1074.001 (Local Data Staging): it detects a dropped script file, not discovery activity |
| **Telemetry** | Sysmon Event ID 11 (File create) — `winlog.event_data.Image`, `winlog.event_data.TargetFilename` |
| **Detection** | Sigma rule matching a `.ps1` file created in `\Windows\Temp\` where the creating process is `powershell.exe` |
| **Test** | Converted from a TCM prebuilt Kibana rule; re-validated against this lab's raw schema |
| **Expected alert** | 1 alert per `.ps1` file written to `\Windows\Temp\` by PowerShell |
| **False positives** | Legitimate PowerShell automation scripts staged in Temp by IT tooling (as noted in the rule's own `falsepositives` field) |
| **Severity** | Low |
| **Tuning** | Exclude known deployment tool script paths once a baseline is established; consider correlating with subsequent execution of the same file (a `.ps1` written then immediately invoked is a much stronger signal than the write alone) |
| **Coverage** | Catches only `.ps1` files written **specifically by `powershell.exe`**, to **specifically** `\Windows\Temp\`. Does **not** cover: scripts written by other processes (a browser, a macro-spawned process, cmd.exe via redirection), other script extensions (`.bat`, `.vbs`, `.js`, `.psm1`), or staging in other common drop locations (`%APPDATA%`, `%USERPROFILE%\Downloads`, `C:\ProgramData`) |
| **Investigation** | Check the full command line of the writing process (or Script Block Logging if available) to see what content was written and why; check whether the file was subsequently executed; check the parent process chain for how this PowerShell session was triggered |
| **Response** | If confirmed malicious: preserve and analyze the dropped script before deletion, terminate any process executing it, isolate the host if follow-on activity is suspected, and check for further payloads staged alongside it |

**Tag mismatch worth flagging explicitly:** this rule's ATT&CK tags (T1082, T1217 — both Discovery techniques) don't match what the detection logic actually does. Writing a `.ps1` file to a Temp directory is a **staging/delivery** action, not a discovery action — nothing here inspects system information or browser data. This mismatch was inherited directly from the original TCM prebuilt rule's tagging and carried through the conversion rather than corrected. Worth relabeling tags to `attack.t1105` (Ingress Tool Transfer) or `attack.t1074.001` (Local Data Staging) to accurately reflect the logic — and worth naming this explicitly in a portfolio write-up as an example of validating inherited tags against actual detection logic rather than trusting a source rule's metadata at face value.

**Note on false positives:** as with the other rules, this was validated against a self-triggered test, not real production noise.