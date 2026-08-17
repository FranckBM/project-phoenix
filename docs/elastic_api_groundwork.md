Elastic Detection Engineering API
Session Notes (Aug 15, 2026)
Summary

Started the Elastic Detection Engineering API backlog item. Got as far as producing a fully validated, Kibana-native EQL rule from Sigma source — proven against live telemetry in Kibana's own rule engine, not just converted and assumed correct. Actual API import (POST to the Detection Engine API) deferred to next session.

Format discovery

sigma-cli's Elasticsearch plugin doesn't register a target literally named elasticsearch — targets are lucene, eql, esql, elastalert. Found the Kibana-importable format via:

powershell

powershell
  sigma list formats eql
  sigma list formats esql

Both eql and esql targets expose a siem_rule_ndjson format — this is the same NDJSON structure Kibana produces when exporting rules from its own UI, making it the correct round-trip format for the Detection Engine API. Went with EQL over ESQL for this first attempt, since EQL is the more mature/stable engine and closer to the Lucene-based approach already used successfully across rules #1–10.

Conversion and correction

Converted rule #1 (Registry Run Key Persistence, T1547.001) as the test case:

powershell

powershell
  sigma convert -t eql -f siem_rule_ndjson --without-pipeline detection-rules\sigma\registry_run_key_persistence.yml -o registry_run_key_persistence_kibana.ndjson

Raw output required two corrections to the generated query field, on top of the now-familiar winlog.event_data. prefix fix:

Field name: EventID → event.code. Sysmon's raw EventID field doesn't exist as a queryable top-level field in this pipeline — event.code is the correct Winlogbeat-populated equivalent.
Operator: event.code:13 → event.code==13. EQL uses == for numeric field comparisons; Lucene-style colon syntax (:) doesn't apply here despite working fine in the Lucene queries used everywhere else in the project. New lab gotcha, worth flagging clearly: the field-prefix fix is consistent across query languages, but operator syntax is not — EQL and Lucene diverge on this specific point.

Final validated query:

any where event.code==13 and winlog.event_data.TargetObject:"*\\CurrentVersion\\Run\\*"
Validation method

Rather than attempt an API import blind, validated the corrected query directly in Kibana's rule builder first:

Rule type: Event Correlation (this is the EQL-specific rule type — initially tried "Custom query," which is for KQL/Lucene only, and got zero results before realizing the rule type itself was wrong, not the query)
Preview: confirmed multiple real alerts generated against win11-rebuild telemetry over a 7-day window
Host/user/process/file columns in the alert view came back empty — expected, consistent with this lab's raw (non-ECS-entity-mapped) Winlogbeat setup, not a bug
Outstanding for next session
 Actual API import — POST the corrected .ndjson file to Kibana's Detection Engine API (/api/detection_engine/rules/_import or similar)
 Requires a Kibana API key scoped for rule management — different scope from the Beats-format key used for Winlogbeat shipping
 Once import works for rule #1, repeat for remaining validated rules
 Minor cosmetic fix: "description" field lost a space during an earlier find-replace pass ("Detectscreation") — harmless to JSON validity but worth a clean pass before this becomes a template for other rules
Rule coverage status (unchanged this session)

9 of 8–10 target rules fully validated. 1 additional rule (#9, Office→ PowerShell) written but unconfirmed pending Office availability. TCM conversion target exceeded (3 of 2–3).