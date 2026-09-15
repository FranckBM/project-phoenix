# Rule #9 — Office Application Spawning PowerShell — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1059.001 — Command and Scripting Interpreter: PowerShell (Execution) / T1204.002 — User Execution: Malicious File (Execution) |
| **Telemetry** | Sysmon Event ID 1 (process creation) — `winlog.event_data.ParentImage`, `winlog.event_data.Image` |
| **Detection** | Sigma rule matching a parent/child process pair: `winword.exe`, `excel.exe`, `powerpnt.exe`, or `soffice.bin` spawning `powershell.exe` or `pwsh.exe` |
| **Test** | Blocked for several sessions on no Office installation in the lab; unblocked by installing LibreOffice and triggering a genuine `soffice.bin` → `powershell.exe` spawn via a minimal Basic macro (`Shell("powershell.exe ...")`), run manually from the macro editor — an authentic parent-child relationship via the real underlying mechanism macro malware uses, not a simulated one |
| **Expected alert** | 1 alert per Office/LibreOffice application directly spawning a PowerShell process |
| **False positives** | Legitimate Office/LibreOffice add-ins or automation scripts that shell out to PowerShell — flagged in the rule itself as uncommon in most environments |
| **Severity** | High |
| **Tuning** | If a legitimate enterprise add-in is confirmed to do this routinely, exclude the specific signed add-in/macro rather than loosening the parent or child process match |
| **Coverage** | Broadened deliberately during conversion to include `soffice.bin` alongside the three Microsoft Office binaries — a genuine coverage improvement over the original scope, not just a workaround for lacking a Microsoft Office license, since any organization running LibreOffice instead of (or alongside) Microsoft Office would otherwise have had a blind spot. Does **not** cover: Office spawning an intermediate process (e.g. `cmd.exe`) which then spawns PowerShell — this rule only catches a *direct* parent-child relationship; a macro-triggered `mshta.exe`, `wscript.exe`, or `rundll32.exe` chain instead of PowerShell; or Office applications not in this list (Outlook, Access) |
| **Investigation** | Check the full PowerShell command line for what's actually being executed; check whether the source document/workbook is known or newly received (email attachment, download); correlate with Script Block Logging (Event 4104) to see the real executed code if the command line itself is short or a launcher; check for Mark-of-the-Web / macro-security-prompt bypass indicators if available |
| **Response** | If confirmed malicious: terminate the process, quarantine the source document, isolate the host if follow-on activity is suspected, and check for persistence dropped by the macro payload (this is a very common initial-access → persistence chain) |

**Worth highlighting in a portfolio write-up:** the path to validating this rule is a good example of not faking a detection to get past a blocker. Simulating the parent-child relationship without a genuine spawning application was explicitly considered and rejected as inauthentic; installing LibreOffice instead produced a real, unscripted process tree via the actual technique's mechanism — and improved the rule's real-world coverage in the process, rather than just working around a lab limitation.

**Note on false positives:** as with the other rules, this was validated against a self-triggered test, not real production noise.