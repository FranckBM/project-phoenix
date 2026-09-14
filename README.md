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
│   ├── sigma/              # Sigma source rules
│   ├── elastic/             # Converted/Kibana-imported rule artifacts
│   └── validation/          # Rule validation notes and test results
├── docs/
│   ├── detection-quality/   # Per-rule quality write-ups (telemetry, FPs, tuning, coverage)
│   └── ...                  # Field mapping notes, lab rebuild checklists, session write-ups
├── threat-hunts/
├── python-tools/
│   └── enrichment_data/     # ATT&CK + asset context lookup tables for the enrichment script
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

### ATT&CK Coverage Matrix

| # | Rule | ATT&CK Technique | Tactic | Status | Quality Doc |
|---|---|---|---|---|---|
| 1 | Registry Run Key Persistence | T1547.001 | Persistence | ✅ Validated, imported | ✅ |
| 2 | PowerShell Hidden Window | T1564.003 / T1059.001 | Defense Evasion / Execution | ✅ Validated | ✅ |
| 3 | reg.exe Run Key Writes | T1112 | Defense Evasion | ✅ Validated | ⬜ |
| 4 | PowerShell Web Download | T1059.001 / T1105 | Execution / C2 | ✅ Validated | ⬜ |
| 5 | MSF PowerShell Payload | T1059 / T1059.001 | Execution | ✅ Validated | ⬜ |
| 6 | Data Archive for Exfil | T1074 / T1074.001 | Collection | ✅ Validated | ⬜ |
| 7 | Defender Tamper | T1562.001 | Defense Evasion | ✅ Validated | ⬜ |
| 8 | Scheduled Task Persistence | T1053.005 | Persistence / Execution | ✅ Validated | ⬜ |
| 9 | Office → PowerShell | T1059.001 / T1204.002 | Execution | ✅ Validated, imported | ⬜ |
| 10 | Suspicious Temp File Write | T1082 / T1217 | Discovery | ✅ Validated | ⬜ |
| 11 | SMB Admin Share Access via net.exe | T1021.002 | Lateral Movement | ✅ Validated, imported, alert fired | ✅ |

**11 of 10 target rules validated — target exceeded.** Detection Quality documentation (telemetry, test method, false positives, tuning, coverage, investigation, response) is in progress: 3 of 11 rules documented so far.

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
- **Alert enrichment script** — takes a raw detection alert and enriches it with ATT&CK technique/tactic metadata and host/user context, producing a readable, analyst-ready alert summary. Currently uses static lookup tables as a stand-in for a real CMDB/asset inventory; a natural next step is hash/IP reputation lookups and live Kibana API integration.

---

## 📚 Write-ups

Every project includes documentation covering:

- Threat scenario
- MITRE ATT&CK mapping
- Detection logic
- Validation
- Lessons learned (including infrastructure gotchas — several real pipeline gaps have been found and fixed over the course of this project, not just clean first-try successes)

---

## 🎯 Current Progress

- ✅ Detection Engineering Fundamentals
- ✅ Sigma Rules — 11 of 10 target rules built and validated
- ✅ Detection-as-Code — CI linting, Elastic Detection Engineering API round-trip proven (twice via API, once via Kibana UI)
- ◐ Detection Quality documentation — 3 of 11 rules documented
- ◐ Python Automation — alert enrichment v1 live; Sysmon parser has a known multi-line field limitation still to fix
- ⬜ Cloud Detection Engineering — next major milestone (AWS CloudTrail/IAM, Azure Entra ID, identity detections)
- ⬜ Portfolio Development — case studies, published coverage matrix, resume/LinkedIn update

---

## 🛠️ Technologies

- Elastic Security
- Sigma
- Python
- Git / GitHub Actions
- Sysmon / Windows Event Logs
- MITRE ATT&CK
- AWS *(Cloud Detection Engineering — in progress)*

---

## 📈 Guiding Principles

Every detection should be:

**Built → Tested → Documented → Reviewed → Improved → Repeat**

This project treats false positives, coverage gaps and pipeline failures as part of the engineering record — not something to clean up before showing the work.