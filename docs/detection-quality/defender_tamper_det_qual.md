# Rule #7 — Windows Defender Real-Time Protection Disabled via PowerShell — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1562.001 — Impair Defenses: Disable or Modify Tools (Defense Evasion) |
| **Telemetry** | Sysmon Event ID 1 (process creation) — `winlog.event_data.Image`, `winlog.event_data.CommandLine` |
| **Detection** | Sigma rule matching PowerShell/pwsh process creation where the command line contains `Set-MpPreference` **and** one of the specific disable flags (`DisableRealtimeMonitoring`, `DisableAntiSpyware`, `DisableBehaviorMonitoring`, `DisableIOAVProtection`) |
| **Test** | Home lab — manually invoked `Set-MpPreference` with a disable flag; validated against live telemetry |
| **Expected alert** | 1 alert per PowerShell invocation disabling one or more Defender protection features |
| **False positives** | Legitimate IT-managed endpoint configuration scripts — flagged in the rule itself as rare in most environments, and genuinely worth alerting on even when legitimate, given the severity of what this action enables |
| **Severity** | High |
| **Tuning** | If this fires in a real environment from a known configuration management tool (e.g. SCCM, Intune baseline scripts), exclude the specific service account or signed script path rather than lowering severity — the action itself stays high-risk regardless of source |
| **Coverage** | Catches only the **PowerShell cmdlet path** (`Set-MpPreference`). Does **not** cover: disabling Defender via the GUI, via direct registry modification (the underlying mechanism `Set-MpPreference` itself writes to), via `MpCmdRun.exe`, or via Group Policy changes pushed from a domain controller — all of which achieve the same outcome through a different telemetry signature |
| **Investigation** | Check the full command line for exactly which protections were disabled and to what value; identify the account and parent process — a script running under a normal user's interactive session is a very different signal than a scheduled/service-account-triggered one; check for follow-on activity immediately after (payload download, execution) since this is typically a precursor step, not the end goal |
| **Response** | Re-enable the disabled Defender features immediately; treat as high-confidence malicious unless proven otherwise given the rule's own false-positive rarity; isolate the host and investigate for payload delivery that likely followed; check for persistence mechanisms that may have been dropped in the window Defender was down |

**Design note:** this rule deliberately requires **both** the cmdlet name and a specific disable flag together (`selection_cmd and selection_disable`), rather than matching on `Set-MpPreference` alone — since that cmdlet is also used for many benign configuration changes (exclusion lists, scan schedules). This is a good tuning decision worth highlighting in a portfolio write-up: it shows narrowing a detection to the actually-risky parameter combination rather than over-alerting on a common admin cmdlet.

**Coverage gap worth noting explicitly:** the registry-based bypass (writing directly to the Defender policy keys that `Set-MpPreference` itself modifies) would not be caught here — a natural companion rule would be a `registry_event` detection on those specific keys, catching the technique regardless of which tool was used to make the change.

**Note on false positives:** as with the other rules, this was validated against a self-triggered test, not real production noise.