# Rule #2 — PowerShell Execution with Hidden Window — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1564.003 — Hide Artifacts: Hidden Window (Defense Evasion) / T1059.001 — Command and Scripting Interpreter: PowerShell (Execution) |
| **Telemetry** | Sysmon Event ID 1 (process creation) — `winlog.event_data.Image`, `winlog.event_data.CommandLine` |
| **Detection** | Sigma rule matching `powershell.exe` process creation where the command line contains the word `hidden` — deliberately a loose substring match rather than an exact `-WindowStyle` flag match |
| **Test** | Home lab, early session — manually invoked PowerShell with a hidden window flag; validated against live telemetry |
| **Expected alert** | 1 alert per PowerShell invocation referencing a hidden window |
| **False positives** | Legitimate scheduled tasks or automation scripts intentionally suppressing the console window; IT-managed deployment/maintenance scripts (as noted in the rule's own `falsepositives` field) |
| **Severity** | Medium |
| **Tuning** | Exclude known-good scheduled task names/paths once a baseline of legitimate hidden-window automation is established |
| **Coverage** | Catches any command-line reference to "hidden" near a window-style flag, including typo'd/misspelled variants (e.g. `-WindowSytle hidden`) that a strict `-WindowStyle` match would miss. Does **not** cover: hidden-window execution achieved without the word "hidden" appearing in the command line (e.g. via a config file, script-internal `$host.UI` manipulation, or a fully obfuscated/encoded command block) |
| **Investigation** | Check the full command line for what's actually being run; identify parent process (legitimate scheduler vs. suspicious spawning process — e.g. Office app, browser); check whether the script/task is signed or known; correlate with Script Block Logging (Event 4104) if available, to see the actual executed code rather than just the launch command |
| **Response** | If confirmed malicious: terminate the process, review for follow-on activity (network connections, file writes, additional process spawns), and check Autostart/Scheduled Tasks locations for how it was triggered if not directly observed |

**Design note (from the rule's own description):** this rule intentionally favors a broad substring match over an exact flag match, based on lab-observed evidence that command-line flags get typo'd or obfuscated. That's a good, evidence-based tuning decision worth calling out explicitly in a portfolio write-up — it shows reasoning from an actual observed gap, not just copying a textbook pattern.

**Note on false positives:** as with rules #1 and #11, this was validated against a self-triggered test, not real production noise — false positives listed are anticipated from technique knowledge, not yet empirically tuned.