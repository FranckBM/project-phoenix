# Python Tools

Small, detection-adjacent tools for Project Phoenix. Standard library only: no dependencies to install.

## Alert enrichment (`enrich_alert.py`)

Takes a detection alert and adds the context an analyst would otherwise look up by hand:

- **ATT&CK context:** technique name and tactics for every technique on the alert, from `enrichment_data/attack_lookup.json`. A sub-technique missing from the table falls back to its parent.
- **Host and user context:** owner, criticality, role and privilege level, from `enrichment_data/asset_inventory.json`, a static stand-in for a real CMDB or asset inventory.

### Input formats

Detected automatically:

| Input | Example |
|---|---|
| Simple alert JSON | `enrichment_data/sample_alert.json` |
| Kibana Security alert document (nested or flattened `kibana.alert.*` keys, optionally inside `_source`) | `enrichment_data/sample_kibana_alert.json` |
| Elasticsearch search response (`{"hits": {"hits": [...]}}`) | output of a Dev Tools query on the alerts index |
| JSON array or NDJSON | several alerts at once |

For Kibana alerts, techniques come from the rule's own threat mapping (`kibana.alert.rule.threat`), preferring sub-techniques. Host, user, process and command line are read from ECS fields first (`host.name`, `user.name`, `process.*`) and then from this lab's raw Winlogbeat fields (`winlog.event_data.*`), because the Windows lab ships raw Sysmon fields rather than ECS-mapped ones. Host matching ignores case, and users match with or without a `DOMAIN\` prefix.

### Usage

```
python enrich_alert.py enrichment_data/sample_alert.json
python enrich_alert.py enrichment_data/sample_kibana_alert.json --json
python enrich_alert.py alerts.ndjson --output enriched.json
```

`--json` prints the enriched structure instead of the readable summary. `--output` writes it to a file. The exit code is 1 for unreadable input, otherwise 0. Missing data never stops a run: each section reports what it couldn't find (for example `host 'X' not found in asset inventory`).

### Sample output

```
================================================================
ALERT: SMB Admin Share Access via net.exe
================================================================
Timestamp   : 2026-10-18T14:17:20.000Z
Severity    : medium

--- ATT&CK Context ---
Technique   : T1021.002 - Remote Services: SMB/Windows Admin Shares
Tactic(s)   : Lateral Movement

--- Host Context ---
Host        : WIN11-REBUILD
Owner       : Franck (lab VM)
Criticality : low
Notes       : Primary detection engineering lab target VM

--- User Context ---
User        : vboxuser
Role        : lab test account
Privilege   : local admin
Notes       : Used for Atomic Red Team test execution; not a real production identity

--- Raw Detection Detail ---
Process     : C:\Windows\System32\net.exe
Command     : net use \\localhost\ADMIN$ /u:WIN11-REBUILD\vboxuser
================================================================
```

### Tests

```
python -m unittest discover tests -v
```

14 tests cover field access across nested and flattened documents, technique extraction, parent fallback, case-insensitive and domain-stripped matching, and every input format. They also run in GitHub Actions on any change under `python-tools/`.

### Limits and next steps

- The ATT&CK table covers the techniques used by Phoenix's 16 rules, not the full framework.
- The asset inventory is static. Natural next steps: a real CMDB or identity source, hash and IP reputation lookups, and pulling alerts straight from the Kibana API.

## Sysmon log parser (`sysmon_parser.py`)

Extracts `TimeCreated`, `Image` and `TargetObject` from a text export of Sysmon events (`sample_sysmon_export.txt`) into `sysmon_output.csv`. Known limitation: values that wrap onto a second line in the export are cut off (visible in the CSV's truncated registry paths).
