Post-Rebuild Validation
Summary

Rebuilt Win11 lab VM validated end-to-end. All four detection rules confirmed working against fresh telemetry. Two new gaps identified and closed: Script Block Logging was missing, and Sigma-converted queries need manual field-prefix correction for this lab's raw (non-ECS) field mapping.

Docs push

Confirmed all prior documentation committed and pushed to main:

field-mapping-notes.md
winlogbeat-template.yml
lab-rebuild-checklist.md
Execution policy fix note (Atomic Red Team)
New findings
1. Winlogbeat was never fully reinstalled post-rebuild
Binary was present (C:\Program Files\Winlogbeat\winlogbeat.exe, dated 8/8) but no Windows service was registered.
Get-Service winlogbeat → "Cannot find any service with service name."
Fix: re-ran .\install-service-winlogbeat.ps1, hit the same PowerShell execution policy block as the Atomic Red Team install. Same fix applies:
powershell
  Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Action item: add explicit Winlogbeat service install + execution policy bypass to lab-rebuild-checklist.md as a required step, not optional.
2. Kibana Discover "stuck on old data" — twice, two different causes
Cause A (Discover classic view): sort order defaulted to ascending on @timestamp, so oldest matching docs (Aug 8 leftovers) displayed first even though fresh data existed. Fix: flip Sort fields to descending.
Cause B (ES|QL): query was missing the FROM winlogbeat-* | source clause — WHERE ... | SORT ... alone throws a parse error, not empty results.
Confirmation method that actually worked: switching to Lens visualization (Explore in Discover → Line chart) showed a clear time-series spike on Aug 11, proving data was landing before we knew why Discover's table view didn't reflect it.
3. Sigma → Lucene conversion requires manual field-prefix correction
sigma convert -t lucene --without-pipeline outputs bare field names (Image, CommandLine, TargetObject), but this lab's index stores everything under winlog.event_data.* (raw, non-ECS-mapped).
Standing rule: every converted query needs winlog.event_data. prepended to each field name before pasting into Discover.
Additionally, Kibana Discover defaults to KQL, not Lucene — escaped characters from Lucene output (\-, \ ) throw parse errors in KQL and must be stripped before running.
4. PowerShell Script Block Logging was not enabled
Rule #4 (PowerShell web download, T1059.001/T1105) initially targeted process_creation / CommandLine, assuming Invoke-WebRequest would appear in the process launch command line.
It doesn't — dropper.ps1 is launched via -file, so cmdlets executed inside the script never appear in Sysmon's Event ID 1 CommandLine field.
Cmdlet-level activity only appears via Script Block Logging (Event ID 4104, winlog.event_data.ScriptBlockText), which is disabled by default.
Enabled via registry:
powershell
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Also required adding a second event_logs entry in winlogbeat.yml:
yaml
  winlogbeat.event_logs:
    - name: Microsoft-Windows-Sysmon/Operational
    - name: Microsoft-Windows-PowerShell/Operational
      event_id: 4104
Action item: add Script Block Logging enablement to the standard rebuild checklist — it's required infrastructure, not optional, for any rule that needs cmdlet-level (not just process-level) visibility.
Rule re-hunt results (post-rebuild)
Rule	Technique	Status	Notes
#1 — Registry Run key persistence	T1547.001	✅ Confirmed	2 hits, matched both dropper runs exactly
#2 — PowerShell hidden window	T1564.003 / T1059.001	✅ Confirmed	2 hits, matched both dropper runs exactly
#3 — reg.exe Run key writes	T1547.001 / T1112	✅ Confirmed	Same 2 events as #1 (overlapping scope)
#4 — PowerShell web download	T1059.001 / T1105	✅ Confirmed (reworked)	Rebuilt to target Event 4104 ScriptBlockText instead of CommandLine; 1 hit (only run after Script Block Logging was enabled)
Investigated anomaly (resolved, benign)

dllhost.exe spawning notepad++.exe with a /Processid:{GUID} argument initially looked suspicious (COM surrogate pattern). Root cause: right-click "Edit with Notepad++" on dropper.ps1 triggers Explorer to load Notepad++'s shell extension via a COM surrogate process — standard, well-documented Windows behavior. Verified via signed binary, matching hashes, normal integrity level, and CLSID registry lookup path (not completed but flagged as the definitive next step if ever needed again).

Outstanding backlog
 Convert 2–3 TCM course prebuilt Kibana rules to Sigma
 Delete old Elastic API key tied to the deleted pre-rebuild VM
 Rule #5 candidate: Defender tamper/disable detection (T1562.001), surfaced from the TCM "Defender Disabled?" flowchart branch