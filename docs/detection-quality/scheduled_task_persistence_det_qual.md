# Rule #8 — Scheduled Task Created via schtasks.exe — Detection Quality

| Field | Detail |
|---|---|
| **ATT&CK technique** | T1053.005 — Scheduled Task/Job: Scheduled Task (Persistence, Privilege Escalation) |
| **Telemetry** | Sysmon Event ID 1 (process creation) — `winlog.event_data.Image`, `winlog.event_data.CommandLine` |
| **Detection** | Sigma rule matching `schtasks.exe` process creation where the command line contains `/create` |
| **Test** | Home lab — manually invoked `schtasks.exe /create` to register a test task; validated against live telemetry |
| **Expected alert** | 1 alert per scheduled task created via `schtasks.exe` |
| **False positives** | Legitimate software installers registering scheduled maintenance tasks (as noted in the rule's own `falsepositives` field) — genuinely common, since many legitimate applications (browsers, updaters, backup tools) register scheduled tasks during install |
| **Severity** | Medium |
| **Tuning** | Exclude known installer/updater task names or the specific vendor binaries that create them once a baseline is established; consider correlating with the task's target action (`/tr` argument) — a task set to run a script from a Temp/Downloads path is a much stronger signal than one pointing at a signed vendor binary |
| **Coverage** | Catches only task creation via `schtasks.exe` with the `/create` flag specifically. Does **not** cover: task creation via PowerShell's `New-ScheduledTaskAction`/`Register-ScheduledTask` cmdlets, direct COM/API calls (`ITaskService`), or modification of an *existing* task (`/change`) rather than creating a new one — a maintained persistence mechanism could be updated without ever hitting `/create` again |
| **Investigation** | Extract the full command line — specifically the `/tr` (task run) argument to see what the task actually executes, and `/sc` (schedule) to see how often; check whether the target binary/script is known-good or suspicious; check the parent process that invoked `schtasks.exe` |
| **Response** | If confirmed malicious: delete the scheduled task (`schtasks /delete`), terminate any process it may have already spawned, isolate the host if broader compromise suspected, and check for other autostart mechanisms (Run keys, services) the same actor may have also planted |

**Coverage gap worth noting explicitly:** the `/create`-only match means this rule has a real blind spot around task *modification* — an adversary editing an existing legitimate task's action (`/change`) to point at malicious code would not trigger this rule at all, despite achieving persistence just as effectively. Worth flagging as a natural v2 addition (a second selection block for `/change`) rather than treating the current scope as complete.

**Note on false positives:** as with the other rules, this was validated against a self-triggered test, not real production noise — though of all the rules so far, this one has among the more plausible real-world false-positive rate given how routinely legitimate software uses scheduled tasks.