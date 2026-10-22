# 🔥 Project Phoenix
### From Senior Security Analyst to Detection Engineer

This project is my personal Detection Engineering portfolio, documenting my transition from Senior Security Analyst to Detection Engineer.

After 12 years working in Security Operations, Incident Response and Threat Detection, I created this repository to move from operating security tools to engineering detections that are scalable, testable and maintainable.

Rather than simply completing courses, Project Phoenix focuses on building a practical Detection Engineering portfolio through hands-on development, validation and documentation — including the mistakes, dead ends and infrastructure gotchas along the way, not just the finished result.

---

## 🎯 Objectives

Project Phoenix focuses on five core areas:

- 🛡️ Detection Engineering
- 🔍 Threat Hunting
- 🐍 Python Automation
- ☁️ Cloud Detection Engineering
- ⚙️ Detection-as-Code

Every detection is built, tested, documented and version controlled.

---

## 📂 Repository Structure

```
Project-Phoenix/
├── detection-rules/
│   ├── sigma/                # Windows Sigma source rules
│   ├── elastic/              # Converted/Kibana-imported rule artifacts
│   └── validation/           # Rule validation notes and test results
├── cloud-detection-lab/      # AWS and Azure detection labs (own README inside)
│   ├── aws/
│   │   ├── config.yaml.template   # Placeholders only; the real config.yaml is gitignored
│   │   └── detection-rules/
│   │       ├── sigma/             # AWS Sigma rules
│   │       └── validation/        # AWS rule validation docs
│   └── azure/
│       ├── ingest_entra_audit.py  # Microsoft Graph audit log -> Elasticsearch ingest
│       ├── config.yaml.template   # Placeholders only; the real config.yaml is gitignored
│       └── detection-rules/
│           ├── sigma/             # Azure Sigma rules
│           └── validation/        # Azure rule validation docs
├── docs/
│   ├── detection-quality/    # Per-rule quality write-ups (telemetry, FPs, tuning, coverage)
│   ├── detection_engineering_metrics.md
│   └── ...                   # Field mapping notes, lab rebuild checklists, session write-ups
├── threat-hunts/
├── python-tools/
│   └── enrichment_data/      # ATT&CK + asset context lookup tables for the enrichment script
├── writeups/
└── assets/
```

---

## 🛡️ Detection Rules

This folder contains:

- Sigma rules
- Elastic implementations
- Detection validation
- ATT&CK mappings
- False positive considerations

### ATT&CK Coverage Matrix — Windows

| # | Rule | ATT&CK Technique | Tactic | Status | Quality Doc |
|---|---|---|---|---|---|
| 1 | Registry Run Key Persistence | T1547.001 | Persistence | ✅ Validated, imported | ✅ |
| 2 | PowerShell Hidden Window | T1564.003 / T1059.001 | Defense Evasion / Execution | ✅ Validated | ✅ |
| 3 | reg.exe Run Key Writes | T1112 | Defense Evasion | ✅ Validated | ✅ |
| 4 | PowerShell Web Download | T1059.001 / T1105 | Execution / C2 | ✅ Validated | ✅ |
| 5 | MSF PowerShell Payload | T1059 / T1059.001 | Execution | ✅ Validated | ✅ |
| 6 | Data Archive for Exfil | T1074 / T1074.001 | Collection | ✅ Validated | ✅ |
| 7 | Defender Tamper | T1562.001 | Defense Evasion | ✅ Validated | ✅ |
| 8 | Scheduled Task Persistence | T1053.005 | Persistence / Execution | ✅ Validated | ✅ |
| 9 | Office → PowerShell | T1059.001 / T1204.002 | Execution | ✅ Validated, imported | ✅ |
| 10 | Suspicious Temp File Write | T1082 / T1217 | Discovery | ✅ Validated | ✅ |
| 11 | SMB Admin Share Access via net.exe | T1021.002 | Lateral Movement | ✅ Validated, imported, alert fired; alert suppression added 2026-10-18 (3 test events gave 2 alerts) | ✅ |

**11 of 10 target rules validated — target exceeded.** All 11 have a Detection Quality write-up (telemetry, test method, false positives, tuning, coverage, investigation, response). Writing them surfaced real findings, for example rules #1/#3 miss the RunOnce key and rule #10's inherited ATT&CK tags did not match its logic.

### ATT&CK Coverage Matrix — AWS (Cloud Detection Lab)

| # | Rule | ATT&CK Technique | Tactic | Status |
|---|---|---|---|---|
| 1 | AWS Root Account Usage | T1078.004 | Initial Access / Persistence / Privilege Escalation / Defense Evasion | ✅ Live in Kibana with alert suppression (root login test: 1 alert, 28 suppressed) |
| 2 | AWS IAM Policy Created, Attached or Modified | T1098.003 | Persistence / Privilege Escalation | ✅ Live in Kibana with alert suppression (CreatePolicy test alerted, ~7m35s event to alert) |
| 3 | AWS Console Login Without MFA | T1078.004 | Initial Access | ✅ Live in Kibana with alert suppression (alerted ~6m44s event to alert; a login with MFA did not alert) |

All three cloud rules are imported into Kibana as live detection rules, validated against real CloudTrail data and trigger-tested end to end. Alert suppression (per identity ARN, 1 hour) was added because a single root login produces dozens of CloudTrail events. The first no-MFA test missed because CloudTrail delivery took about 5 minutes, longer than the rule's 4 minute look-back, so the look-back was raised to 10 minutes on all three rules. See [`cloud-detection-lab/`](cloud-detection-lab/) for the pipeline, secrets handling and gotchas, and the validation docs for the test evidence.

### ATT&CK Coverage Matrix — Azure (Cloud Detection Lab)

| # | Rule | ATT&CK Technique | Tactic | Status |
|---|---|---|---|---|
| 1 | Entra ID Application Credentials Changed | T1098.001 | Persistence / Privilege Escalation | ✅ Live in Kibana with alert suppression (alerted ~5m32s event to alert; credential removals also match) |

The Azure side runs on Entra ID audit logs only. The lab tenant is on the Free tier, and exporting sign-in logs needs a P1 or P2 licence, so sign-in based detections are out of scope for now. A wildcard filter meant to separate credential additions from removals returned nothing on a populated field, so the rule currently covers both; the cause is not yet known and is recorded in the validation doc.

---

## ☁️ Cloud Detection Lab

An AWS detection pipeline built end to end:

```
CloudTrail (multi-region, management events)
    ↓
S3 → SQS
    ↓
Elastic Serverless Forwarder (Lambda)
    ↓
Elasticsearch data stream logs-aws.cloudtrail-default
```

Four real pipeline gotchas were found and documented (greyed-out managed integration mode on serverless, a separate S3 permission parameter behind a 403, CloudTrail data sitting unparsed because integration assets were never installed, and CloudTrail delivery taking longer than a rule's look-back window).

The Azure side pulls Entra ID audit logs from Microsoft Graph with a small Python script (read-only app registration, client credentials) and indexes them into a data stream. Real tenant IDs, client secrets, endpoints and API keys are never committed; only placeholder templates are.

---

## 🔍 Threat Hunts

Each hunt follows the same methodology:

```
Hypothesis
    ↓
Telemetry Collection
    ↓
Investigation
    ↓
Detection Gap
    ↓
New Detection
    ↓
Documentation
```

---

## 🐍 Python Tools

Python is used only where it solves a Detection Engineering problem — not as a general-purpose scripting exercise.

**Current tools:**
- **Sysmon log parser** — extracts `Image`/`TargetObject`/`CommandLine` from a raw Sysmon export into a clean CSV
- **Entra audit log ingest** — polls Microsoft Graph audit logs and bulk-indexes them into Elasticsearch, idempotently (event id as document id, so overlapping polls cause no duplicates); tested against mocked Graph and Elastic responses, then live
- **Alert enrichment script** — takes a raw detection alert and enriches it with ATT&CK technique/tactic metadata and host/user context, producing a readable, analyst-ready alert summary. Currently uses static lookup tables as a stand-in for a real CMDB/asset inventory; a natural next step is hash/IP reputation lookups and live Kibana API integration.

---

## 📊 Metrics

[`docs/detection_engineering_metrics.md`](docs/detection_engineering_metrics.md) separates what can be measured honestly from what cannot yet:

- **Measured:** ATT&CK coverage (6 of 14 tactics on the Windows side) and detection latency: ~3m49s from trigger to alert on Windows rule #11, ~7m35s and ~6m44s from CloudTrail event to alert on two AWS rules, and ~5m32s from Entra audit event to alert on the Azure rule. CloudTrail delivery and ingest alone varied between about 2m36s and 5m06s, on top of the 5-minute rule schedule. Each figure is a single observation.
- **Blocked on real traffic, deliberately not claimed:** alert volume, false positive rate, precision

---

## 📚 Write-ups

Every project includes documentation covering:

- Threat scenario
- MITRE ATT&CK mapping
- Detection logic
- Validation
- Lessons learned (including infrastructure gotchas — several real pipeline gaps have been found and fixed over the course of this project, not just clean first-try successes)

**Case studies:**
- [A correct rule that missed its own test](writeups/case-study-cloudtrail-delivery-vs-rule-lookback.md) — CloudTrail delivery delay vs. a rule's look-back window, found by a live test and fixed on all three AWS rules

---

## 🎯 Current Progress

- ✅ Detection Engineering Fundamentals
- ✅ Sigma Rules — 11 of 10 target rules built and validated
- ✅ Detection-as-Code — CI linting, Elastic Detection Engineering API round-trip proven (twice via API, once via Kibana UI)
- ✅ Detection Quality documentation — 11 of 11 rules documented
- ✅ Detection Engineering Metrics methodology — coverage and latency measured; volume/FP/precision explicitly blocked on real traffic
- ◐ Python Automation — alert enrichment v1 live; Sysmon parser has a known multi-line field limitation still to fix
- ◐ Cloud Detection Engineering — AWS pipeline built with 3 detections live; Azure Entra ID audit-log pipeline built with 1 detection live (4 cloud detections, all with alert suppression and validated end to end); next: further Azure and AWS rules as time allows
- ◐ Portfolio Development — first case study written; more case studies, LinkedIn-ready presentation and resume/LinkedIn update still to do

---

## 🛠️ Technologies

- Elastic Security
- Sigma
- Python
- Git / GitHub Actions
- Sysmon / Windows Event Logs
- MITRE ATT&CK
- AWS (CloudTrail, S3, SQS, Lambda, IAM)
- Azure (Microsoft Entra ID audit logs, Microsoft Graph)

---

## 📈 Guiding Principles

Every detection should be:

**Built → Tested → Documented → Reviewed → Improved → Repeat**

This project treats false positives, coverage gaps and pipeline failures as part of the engineering record — not something to clean up before showing the work.