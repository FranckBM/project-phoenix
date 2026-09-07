# Rule #1 — Registry Run Key Persistence via Sysmon — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder (Persistence, Privilege Escalation) |
| **Telemetry** | Sysmon Event ID 13 (Registry value set) — `winlog.event_data.TargetObject` |
| **Detection** | Sigma rule matching registry writes where `TargetObject` contains `\CurrentVersion\Run\` |
| **Test** | Home lab, early session — manually created/modified a Run key value; validated against live telemetry |
| **Expected alert** | 1 alert per registry write to a matching Run key path |
| **False positives** | Legitimate software installers registering startup entries; IT-managed software deployment tools (as noted in the rule's own `falsepositives` field) |
| **Severity** | Medium |
| **Tuning** | Exclude known-good vendor paths/binaries once a baseline of legitimate installer activity is established; consider correlating with the writing process (Sysmon Event ID 1) to flag cases where an unusual process — e.g. a script interpreter rather than an installer — performs the write |
| **Coverage** | Catches writes specifically to `\CurrentVersion\Run\`. Does **not** cover: `RunOnce` keys, the `Wow6432Node` 32-bit equivalents on 64-bit systems, or the `HKCU`-vs-`HKLM` distinction — the `TargetObject|contains` match is path-fragment-only, so it will catch either hive as long as `\CurrentVersion\Run\` appears, but won't catch `RunOnce` or other autostart locations (Startup folder, services, WMI subscriptions — the last two outside this rule's scope entirely) |
| **Investigation** | Identify the writing process and its parent; check whether the value name/binary path is known-good or newly seen; check binary signing/reputation if available; check timing against other suspicious activity (initial access, download activity) |
| **Response** | If confirmed malicious: remove the registry value, terminate any process spawned from it, isolate the host if broader compromise suspected, and check `RunOnce` and other Autostart locations for related persistence the actor may have also planted |

**Coverage gap worth noting explicitly:** since the detection only matches `\CurrentVersion\Run\` and not `RunOnce`, an adversary using the `RunOnce` key instead would not be caught by this rule as written. Worth flagging as a known limitation rather than an oversight — a natural next iteration would broaden the match to include `RunOnce` as well.

**Note on false positives:** as with the other rules, this was validated against a self-triggered test in the lab, not real production noise — false positives listed are anticipated from technique knowledge, not yet empirically tuned.