# Rule #3 — Registry Run Key Modification via reg.exe — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (Persistence) / T1112 — Modify Registry (Defense Evasion) |
| **Telemetry** | Sysmon Event ID 13 (Registry value set) — `winlog.event_data.Image`, `winlog.event_data.TargetObject` |
| **Detection** | Sigma rule matching a registry write to `\CurrentVersion\Run\` where the writing process is specifically `reg.exe` |
| **Test** | Home lab, early session — manually invoked `reg.exe` to write a Run key value; validated against live telemetry |
| **Expected alert** | 1 alert per `reg.exe`-driven write to a matching Run key path |
| **False positives** | IT-managed deployment scripts or Group Policy startup scripts that use `reg.exe` intentionally; legacy software installers that shell out to `reg.exe` instead of using native registry APIs (both noted in the rule's own `falsepositives` field) |
| **Severity** | High |
| **Tuning** | Exclude known deployment tool paths/service accounts once a baseline of legitimate `reg.exe`-based provisioning is established; the severity is appropriately set high since legitimate software rarely needs to use this exact mechanism (most installers use native registry APIs directly, as the rule's own description notes) |
| **Coverage** | Deliberately narrower than rule #1 (Registry Run Key Persistence via Sysmon) by design — this rule only fires when **`reg.exe` specifically** performs the write, giving a higher-fidelity, living-off-the-land-focused signal, at the cost of missing writes performed via other means (PowerShell's `Set-ItemProperty`, direct API calls, or a compiled binary writing to the registry programmatically) — those are covered by rule #1's broader match instead. Also inherits the same `RunOnce` gap noted on rule #1: matches `\CurrentVersion\Run\` only, not `RunOnce` |
| **Investigation** | Identify the parent process invoking `reg.exe` and the full command line (which key/value was written, and to what); check whether this is a known deployment pattern or a newly observed one; check timing against other suspicious activity (initial access, a preceding download) |
| **Response** | If confirmed malicious: remove the registry value, terminate any process spawned from it, isolate the host if broader compromise suspected, and check `RunOnce` and other Autostart locations (Startup folder, services, WMI subscriptions) for related persistence |

**Design note worth highlighting:** this rule and rule #1 are a genuinely good pair to discuss together in a portfolio — they demonstrate intentional detection layering (broad catch-all + narrow high-fidelity signal) rather than one rule trying to do everything. Worth cross-referencing both write-ups to make that relationship explicit rather than leaving it implicit.

**Note on false positives:** as with the other rules, this was validated against a self-triggered test, not real production noise.