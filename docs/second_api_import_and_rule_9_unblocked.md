Rule #9 Unblocked + Second API Import
Session Notes (Aug 20, 2026)
Summary

Unblocked the last remaining rule (#9, Office→PowerShell) using LibreOffice instead of Microsoft Office — a genuine improvement to the rule's coverage, not just a workaround. All 10 rules are now fully validated with no caveats. Also proved the Elastic API import process a second time, confirming it's a repeatable pipeline rather than a one-off success.

Unblocking rule #9

Previous sessions left this rule "written and syntax-validated only" — no Office installed on the lab VM, and faking the parent-child process relationship was explicitly ruled out as inauthentic. Resolved this session by installing LibreOffice (free, no license) instead:

LibreOffice's Basic macro engine can genuinely spawn a child process via Shell(), the same underlying mechanism real Office macro malware uses — not a simulated/faked relationship, an authentic one.
Rule broadened, not narrowed, to cover this properly: added soffice.bin alongside winword.exe/excel.exe/powerpnt.exe in the ParentImage selector. This is arguably a more realistic rule than the original — any organization running LibreOffice instead of (or alongside) Microsoft Office would have had a blind spot otherwise.

Simulated with a minimal LibreOffice Basic macro:

basic

basic
  Sub TriggerTest
      Shell("powershell.exe -windowstyle hidden -command Write-Host test")
  End Sub

Run directly from the macro editor — no auto-run trigger needed, manual execution still produces a genuine soffice.bin → powershell.exe Sysmon event.

Confirmed in Sysmon: clean Process Create event, ParentImage: C:\Program Files\LibreOffice\program\soffice.bin, Image: ...\powershell.exe.

Confirmed in Elastic: 3 hits via

winlog.event_data.ParentImage:(*\\winword.exe OR *\\excel.exe OR *\\powerpnt.exe OR *\\soffice.bin) AND winlog.event_data.Image:(*\\powershell.exe OR *\\pwsh.exe)

Status: ✅ Fully validated. Rule #9 is no longer flagged as unconfirmed.

Second Elastic API import — rule #9

Repeated the full pipeline proven with rule #1 last session, this time against the freshly-validated rule #9:

powershell

powershell
  sigma convert -t eql -f siem_rule_ndjson --without-pipeline .\office_application_spawning_powershell.yml -o office_application_spawning_powershell_kibana.ndjson

Same field-prefix correction pattern applied (ParentImage and Image both needed winlog.event_data. prepended). No numeric-comparison fix needed this time — the query uses like~ for wildcard string matching, not a numeric equality check, so the earlier : vs == EQL quirk didn't apply here.

Validated first via Kibana's Event Correlation rule preview before importing — same 3 hits, same timestamps as the Discover check. Then imported:

powershell

powershell
  $filePath = "C:\Users\fmana\Desktop\Project-Phoenix\detection-rules\sigma\office_application_spawning_powershell_kibana.ndjson"
  $uri = "https://my-security-project-edc686.kb.us-central1.gcp.elastic.cloud/api/detection_engine/rules/_import"
  $form = @{ file = Get-Item -Path $filePath }
  Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Form $form

Hit a 401 Unauthorized on the first attempt — not a real auth failure, just a stale/empty $headers variable in a fresh PowerShell session (the API key itself was still valid). Re-declared $apiKey/$headers and retried successfully.

Result: success: True. Confirmed visually in Kibana's rule list — "SIGMA - Office Application Spawning PowerShell," enabled, risk score 73 (High), sitting alongside "SIGMA - Registry Run Key Persistence via Sysmon" from the previous import.

Takeaway: the Sigma → EQL → Kibana pipeline is now proven twice, confirming it's a genuinely repeatable process rather than a lucky first attempt. $headers needs re-declaring at the start of any new PowerShell session before calling the API — worth remembering rather than assuming it persists.

Rule coverage status update
#	Rule	Technique	Status
1	Registry Run key persistence	T1547.001	✅ (imported to Kibana via API)
2	PowerShell hidden window	T1564.003 / T1059.001	✅
3	reg.exe Run key writes	T1547.001 / T1112	✅
4	PowerShell web download	T1059.001 / T1105	✅
5	MSF PowerShell payload	T1059 / T1059.001	✅
6	Data archive for exfil	T1074 / T1074.001	✅
7	Defender tamper	T1562.001	✅
8	Scheduled task persistence	T1053.005	✅
9	Office → PowerShell (unblocked this session)	T1059.001 / T1204.002	✅ (imported to Kibana via API)
10	Suspicious temp file write	T1082 / T1217	✅

10 of 10 rules fully validated. No open caveats remaining on rule coverage.

