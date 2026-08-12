TCM Rule Conversion & Sysmon Visibility Gap
Summary

Converted two of TCM's prebuilt Kibana rules to Sigma, simulated both in the lab, and found + fixed a real Sysmon configuration gap along the way. Also closed out a standing security hygiene item (old API key deletion).

Completed
Security hygiene
✅ Deleted the old Elastic API key tied to the pre-rebuild VM.
Rule conversion #1 — Potential MSF PowerShell Payload
Source: TCM prebuilt Kibana rule (d436a6bf-...)
ATT&CK: T1059 / T1059.001 (Command and Scripting Interpreter — PowerShell)
Conversion note: original query used ECS-normalized fields (process.command_line, message) from an Elastic Agent/Fleet pipeline — a bigger mismatch than the usual field-prefix issue, since this lab's raw Winlogbeat setup has no process.* fields at all. Rewritten against winlog.event_data.CommandLine, dropping the message field match pending separate verification.
Simulated with:
powershell
  cmd.exe /c powershell.exe -windowstyle hidden -nop -command "Write-Host test"
Status: ✅ Validated — 3 hits in Elastic against live telemetry.
Rule conversion #2 — Data Archive for Potential Exfil
Source: TCM prebuilt Kibana rule (f1e24a8a-...)
ATT&CK: T1074 / T1074.001 (Data Staged — Local)
Conversion note: original query split file.path / file.name (ECS); raw Sysmon combines these into a single TargetFilename field. Query restructured to match the combined path.
Simulated with:
powershell
  Compress-Archive -Path C:\Windows\System32\drivers\etc\hosts -DestinationPath C:\Windows\Temp\test_archive.zip
Status: ✅ Validated — 1 hit in Elastic, after fixing a Sysmon config gap (below).
Key finding: Sysmon FileCreate visibility gap

Rule #2 initially produced zero telemetry despite the simulation command running successfully and Sysmon confirmed healthy and logging other event types. Root cause: this lab's Sysmon config uses an allowlist for FileCreate (Event ID 11):

xml
<FileCreate onmatch="include">
    <TargetFilename condition="contains">\Start Menu</TargetFilename>
    <TargetFilename condition="contains">\Downloads\</TargetFilename>
    <TargetFilename condition="end with">.exe</TargetFilename>
    <TargetFilename condition="end with">.dll</TargetFilename>
    ... (no .zip entry)
</FileCreate>

Since .zip wasn't in the allowlist and C:\Windows\Temp\ isn't a watched path, the file creation was invisible to Sysmon regardless of how correct the Sigma rule's logic was. This was a visibility problem, not a detection-logic problem — an important distinction to be able to articulate clearly (good Month 3 case-study material).

Fix applied:

xml
<TargetFilename condition="end with">.zip</TargetFilename>

Added inside the same <FileCreate onmatch="include"> block in sysmonconfig-export.xml, then reloaded live via:

powershell
sysmon64 -c C:\Users\vboxuser\Downloads\Sysmon\sysmonconfig-export.xml

(Required an elevated/Administrator PowerShell session — standard user sessions get "Access is denied" on Sysmon service operations.)

Action item: consider whether other likely-relevant extensions are missing from the same allowlist (e.g. .7z, .rar, .tar, .iso) since real staging behavior isn't limited to .zip.

Troubleshooting notes (environmental, not detection-related)
Windows Update mid-session caused a required reboot; clipboard paste into PowerShell stopped working until after the restart.
Get-WinEvent against the Sysmon channel requires an elevated session — same "unauthorized operation" pattern as the earlier execution-policy issue, different command.
sysmon64 -c piped through PowerShell (| Select-String) silently returns empty matches due to UTF-16 console output encoding — redirect to a file and open in Notepad instead when searching Sysmon's live config.
Rule coverage status update
Rule	Technique	Status
#1 — Registry Run key persistence	T1547.001	✅
#2 — PowerShell hidden window	T1564.003/T1059.001	✅
#3 — reg.exe Run key writes	T1547.001/T1112	✅
#4 — PowerShell web download	T1059.001/T1105	✅
#5 — MSF PowerShell payload (new)	T1059/T1059.001	✅
#6 — Data archive for exfil (new)	T1074/T1074.001	✅
