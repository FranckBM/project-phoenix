# Rule #5 — Potential MSF PowerShell Payload Observed — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1059 — Command and Scripting Interpreter / T1059.001 — PowerShell (Execution) |
| **Telemetry** | Sysmon Event ID 1 (process creation) — `winlog.event_data.Image`, `winlog.event_data.CommandLine` |
| **Detection** | Sigma rule matching a `cmd.exe` process whose command line contains all three of: `powershell`, `hidden`, `nop` — markers commonly present in msfvenom-generated PowerShell payloads (hidden window + NOP sled) |
| **Test** | Converted from a TCM prebuilt Kibana rule; re-validated against this lab's raw schema |
| **Expected alert** | 1 alert per `cmd.exe` invocation containing all three obfuscation markers |
| **False positives** | Legitimate scripts coincidentally combining these three terms — flagged in the rule itself as uncommon |
| **Severity** | Low |
| **Tuning** | Given how specific the three-term combination is, false positives should be rare; if any appear, tune by excluding the specific known-legitimate script/tool rather than loosening the match, since loosening risks losing detection of the actual technique |
| **Coverage** | Catches the specific `powershell` + `hidden` + `nop` combination inside a `cmd.exe` command line only. Does **not** cover: PowerShell payloads invoked without a `cmd.exe` intermediary (i.e. `powershell.exe` launched directly), payloads using different msfvenom output flags or a different obfuscation style, or encoded/base64 payloads where these literal strings wouldn't appear in plaintext |
| **Investigation** | Extract the full command line to see the actual payload content; check the parent process of `cmd.exe` (how did this get triggered — user execution, another process, a macro); check for follow-on network connections (msfvenom payloads typically call back to a C2 listener); correlate with Script Block Logging (Event 4104) if available |
| **Response** | If confirmed: terminate the process chain, isolate the host, and treat as likely active compromise given this pattern strongly suggests a Metasploit-generated payload rather than a benign coincidence; check for persistence mechanisms that may have been dropped alongside |

**Discrepancy worth flagging:** the rule's own description says it detects "**cmd.exe spawning** a PowerShell payload," which implies a parent-child relationship check (`ParentImage`). But the actual logic (`selection_parent: Image|endswith: '\cmd.exe'`) matches on `Image`, not `ParentImage` — meaning it detects **`cmd.exe` itself being launched** with this suspicious command line, not `cmd.exe` spawning a separate PowerShell child process. The field name `selection_parent` is a naming artifact left over from how the logic was likely originally conceived, not a reflection of what the rule actually checks. This doesn't break detection in the common case — msfvenom-generated payloads are frequently launched exactly this way, as a single `cmd.exe` command embedding a PowerShell one-liner — but it's worth correcting either the description or the logic (rename `selection_parent` to `selection_process`, or add a genuine `ParentImage`-based variant) so the rule's documentation matches what it actually does. Good catch to include in a portfolio write-up — shows you read your own rule logic critically rather than trusting field names at face value.

**Note on false positives:** as with the other rules, this was validated against a self-triggered test, not real production noise.