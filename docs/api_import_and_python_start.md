Elastic API Import + First Python Script

Summary

Two-part session. Closed out the Elastic Detection Engineering API backlog item with a live API import, then kicked off the Python Sysmon parsing script from scratch — went from "open a file and print it" to a working Sysmon-to-CSV parser in one sitting.

Part 1 — Elastic Detection Engineering API (closed out)

Picked up from last session's groundwork (validated EQL query for rule #1, never actually imported). Finished the loop:

Created a Kibana API key scoped for rule management, used the Encoded format (correct one for Authorization: ApiKey header use — Beats/Logstash formats are for those tools' own config syntax, not direct API calls).
Confirmed auth with a read-only test call against /api/detection_engine/rules/_find — returned the existing rule list (11 rules, including several TCM prebuilts not yet converted: Powershell Invoke-WebRequest Downloading a Bat File, Powershell Execution via a Bat File, Data Exfiltration via FTP — noted as future conversion candidates, not done today).
Confirmed rule #1's rule_id didn't collide with anything existing.
Imported via the dedicated import endpoint (multipart form data, not a raw JSON POST):

powershell

powershell
  $filePath = "C:\Users\fmana\Desktop\Project-Phoenix\registry_run_key_persistence_kibana.ndjson"
  $uri = "https://my-security-project-edc686.kb.us-central1.gcp.elastic.cloud/api/detection_engine/rules/_import"
  $form = @{ file = Get-Item -Path $filePath }
  Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Form $form
Result: success: True, success_count: 1, zero errors. Verified via _find that "SIGMA - Registry Run Key Persistence via Sysmon" now sits natively in Kibana's rule list.

Full round-trip proven and closed: Sigma source → sigma convert -t eql -f siem_rule_ndjson → field/operator corrections → validated in Kibana rule preview → imported via API → confirmed live. This pipeline is now repeatable for any of the other 9 validated rules whenever needed.

Part 2 — Python: Sysmon log parsing script (started)

First hands-on Python session, working ahead of the book (only 5 of Sweigart's free video lectures watched so far) — learned each concept in-context against real data rather than pre-reading chapters first.

Setup gotcha

Out-File with a host-machine path fails from inside the VM — VM and host are separate filesystems (different usernames too: vboxuser vs fmana). Exported inside the VM to the VM's own Desktop, then bridged the file to the host via clipboard (Get-Content ... | Set-Clipboard, paste into a new VS Code file on the host).

Build progression
Read a file: open() + .read() — confirmed Python could open and print the raw Sysmon export.
Line-by-line filtering: for line in f: + if "TargetObject" in line: — introduced substring matching with in. Surfaced a real data quirk: PowerShell's Format-List output wraps long lines, so some field values got split across two physical lines in the export — noted as a known limitation for this raw text approach, to be solved properly with regex later (Ch. 7).
Clean extraction: .strip() + .split(":", 1) — stripped the field label and whitespace, leaving just the value. The 1 limit on split was necessary since registry paths and file paths contain colons themselves (e.g. C:\WINDOWS) and a naive split would break on those too.
Structured grouping — dictionaries: built a current_event = {} dictionary per event, detecting new events via the TimeCreated field as a natural boundary marker, appending each completed dictionary to an events list. Covered the classic gotcha of needing an extra if current_event: check after the loop ends, to catch the last event (which has no following TimeCreated line to trigger its own save).
CSV output: csv.writer, looping over events and writing TimeCreated, Image, TargetObject per row. Used .get(key, "") instead of direct dictionary indexing — safer against missing fields on inconsistent real-world data.
Result

sysmon_output.csv generated successfully — first working version of the Sysmon log parsing script backlog item.

Known limitation to revisit

The line-wrapping issue from step 2 means any field value long enough to wrap in the original Format-List export will currently import truncated or incomplete into the parser. Not fixed today — flagged as a natural next-step problem once regex (Ch. 7) is covered, since regex can handle multi-line/wrapped patterns that simple line-by-line reading can't.

Rule coverage / backlog status (unchanged rule-wise this session)

9 of 8–10 target rules fully validated. 1 additional rule (#9, Office→ PowerShell) written but unconfirmed. TCM conversion target exceeded (3 of 2–3 done; 3 more TCM prebuilts identified as future candidates via today's API rule list, not yet converted).