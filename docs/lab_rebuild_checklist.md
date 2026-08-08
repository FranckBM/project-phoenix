# Lab Rebuild Checklist

Reference for rebuilding the Windows 11 lab VM from scratch (e.g. after an
evaluation license expires). Goal: get from a blank VM to a fully working
Sysmon → Winlogbeat → Elastic pipeline, with Atomic Red Team ready to run,
without repeating the debugging already done.

---

## 1. Windows 11 base

- Use Microsoft's official Windows 11 Enterprise Evaluation VM image (fresh
  90-day activation clock on each new download, rather than fighting
  `slmgr /rearm` limits on an aging install).

## 2. VirtualBox settings (host-side, not VM state)

- **Settings → Storage**: confirm an optical drive exists on the controller
  (needed to mount the Guest Additions ISO). Some minimal VM configs ship
  with no optical drive attached at all.
- **Settings → General → Advanced**: set **Shared Clipboard** to
  **Bidirectional** (and Drag'n'Drop if wanted).
- Inside the VM: **Devices → Insert Guest Additions CD image...**, run
  `VBoxWindowsAdditions.exe` from the mounted drive, reboot.
- Take a snapshot immediately after this baseline is confirmed working —
  e.g. "Clean + Guest Additions" — before installing anything else.

## 3. Sysmon

1. Download Sysmon from Microsoft Sysinternals:
   https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Download SwiftOnSecurity's Sysmon config (comprehensive logging,
   much better coverage than Sysmon's bare defaults):
   https://github.com/SwiftOnSecurity/sysmon-config
3. Extract both. Put the config XML in the **same folder** as
   `Sysmon64.exe` so it can be referenced by filename alone.
4. Open PowerShell **as Administrator**, `cd` into that folder.
5. Install:
   ```powershell
   .\Sysmon64.exe -i sysmonconfig-export.xml -accepteula
   ```
   Note the `.\` prefix — PowerShell won't run a file from the current
   directory by bare filename alone (unlike cmd.exe). Forgetting this
   produces a "not recognized" error even though the file is right there.
6. Confirm it's running: `Get-Service Sysmon*` should show `Running`.
7. Snapshot: "Clean + Sysmon".

## 4. Winlogbeat

Full known-good config template: `docs/winlogbeat-template.yml` in this repo.

1. Download Winlogbeat (matching your Elastic Stack version) from
   https://www.elastic.co/downloads/beats/winlogbeat
2. Extract directly to `C:\Program Files\Winlogbeat` (if the zip nests
   itself in a versioned subfolder, flatten it with `robocopy`:
   `robocopy "<nested-folder>" "C:\Program Files\Winlogbeat" /E /MOVE`)
3. Copy `docs/winlogbeat-template.yml` from this repo into
   `C:\Program Files\Winlogbeat\winlogbeat.yml`, then:
   - Replace the endpoint placeholder with your real serverless URL,
     **including `:443`** (serverless doesn't use the classic 9200).
   - Generate a fresh API key in Kibana → Stack Management → API keys,
     using the **Beats** format specifically (not "Encoded" — that
     format causes a 401 "invalid ApiKey value" error that looks like
     a wrong key but isn't).
   - Double-check the `event_logs` channel name has no stray trailing
     characters (a malformed name fails silently — Winlogbeat runs with
     zero errors but ships zero events forever).
4. Validate before running live:
   ```powershell
   cd "C:\Program Files\Winlogbeat"
   .\winlogbeat.exe test config -c winlogbeat.yml -e
   .\winlogbeat.exe test output -c winlogbeat.yml -e
   ```
   `test output` should end in `talk to server... OK`.
5. Run it:
   ```powershell
   .\winlogbeat.exe -c winlogbeat.yml -e
   ```
6. Confirm in Kibana Discover: `agent.type: "winlogbeat"` should return
   documents. Note this lab's data uses **raw Winlogbeat fields**
   (`winlog.event_data.*`), not ECS field names — see
   `docs/field-mapping-notes.md` for the translation table.
7. Snapshot: "Winlogbeat working".

## 5. Atomic Red Team

```powershell
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser

IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

Snapshot: "Atomic installed".

## 6. Custom adversary simulation (optional, for repeatable attack testing)

Local dropper script pattern used previously (adapted from an Attack
Scenario 3 lab payload, hosted on a Parrot attacker VM via a Python HTTP
server):

```powershell
cd C:\FranckAtomicLabs\Scripts
powershell.exe -ExecutionPolicyBypass -File .\Invoke-Dropper.ps1
```

**Known issue hit before:** `Invoke-WebRequest` failing with "Unable to
connect to the remote server" — root cause was the Python HTTP server on
the Parrot attacker VM simply not running. Fix: confirm connectivity first
with `Test-NetConnection <attacker-ip> -Port 8000` before assuming a code
or network config problem.

---

## Rule backlog (from this custom attack chain — MITRE-mapped, ready to build)

| Idea | MITRE | Status |
|---|---|---|
| Registry Run Key Persistence | T1547.001 | Done — rule #1 |
| PowerShell Hidden Window Execution | T1564.003 / T1059.001 | Done — rule #2 |
| Registry Run Key via reg.exe | T1547.001 / T1112 | Done — rule #3 |
| PowerShell download (`Invoke-WebRequest`) | T1059.001 / T1105 | Not started |
| Suspicious execution from `C:\Windows\Temp\` | — | Not started |
| Known payload filenames (`Keylogger.ps1`/`Exfil.ps1`) | — | Effectively covered by rules #2/#3, but could be its own explicit rule |
| Connection to attacker IP | — | Lab-specific IOC; good example of IOC-based vs. behavioral detection for write-ups, lower long-term value as a portfolio rule |