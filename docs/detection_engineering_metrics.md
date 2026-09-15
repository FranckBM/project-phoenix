# Detection Engineering Metrics — Methodology & Current State

## Purpose

This document defines the metrics used to evaluate detection quality across
Project Phoenix's rule set, and honestly separates what can currently be
measured from what requires data this lab doesn't yet have.

A common failure mode in learning projects is treating "the rule fires" as
the finish line. This document is the deliberate next step: **proving a
rule is good, not just that it works.**

## The metrics, defined

| Metric | Definition | Requires |
|---|---|---|
| **Coverage** | Which ATT&CK techniques/tactics have a detection | Rule set + ATT&CK mapping |
| **Detection latency** | Time between the triggering event occurring and the alert firing | Timestamped test event + timestamped alert |
| **Alert volume** | How many alerts a rule generates over a given period | Sustained real (or realistic) traffic |
| **False positive rate** | Proportion of alerts that are not actually malicious | Real production or production-like traffic, reviewed by an analyst |
| **Precision** | Proportion of alerts that are true positives (inverse framing of FP rate) | Same as above |
| **Mean Time to Detect (MTTD)** | Average time from an attacker action to detection, across many incidents | Multiple real incidents over time |

## What can actually be measured right now

### Coverage — measurable, current state

11 of 11 rules mapped to ATT&CK techniques, spanning:

| Tactic | Techniques covered |
|---|---|
| Persistence | T1547.001, T1053.005 |
| Privilege Escalation | T1547.001, T1053.005 |
| Defense Evasion | T1564.003, T1112, T1562.001 |
| Execution | T1059, T1059.001, T1204.002 |
| Command and Control | T1105 |
| Collection | T1074, T1074.001 |
| Lateral Movement | T1021.002 |
| Discovery *(tagged, logic mismatch — see rule #10's quality doc)* | T1082, T1217 |

**6 of 14 MITRE ATT&CK tactics** have at least one detection. Credential
Access, Discovery (genuinely), Exfiltration, Reconnaissance, Resource
Development, Initial Access, and Impact remain uncovered — this is the
honest gap the coverage matrix should show, not something to obscure.

### Detection latency — measurable, clean data point obtained

**Initial measurement** (rule #11's original validation session,
2026-09-01) produced a misleading ~60-minute figure, dominated by
pipeline debugging time (the missing Winlogbeat Security channel fix)
rather than the rule's actual response time. Flagged at the time as
needing a clean, isolated re-measurement.

**Clean re-measurement (2026-09-15):**

- **Triggering event** (`net.exe` process creation, Sysmon `UtcTime`):
  `16:19:09.616` UTC
- **Alert fired** (Kibana `@timestamp`, converted from UTC+1 display):
  `16:22:58.311` UTC
- **Clean detection latency: 3 minutes 48.7 seconds**

This is consistent with expectations: the rule runs on a 5-minute
schedule, and Elastic's detection engine evaluates within/ahead of that
window rather than always waiting the full interval — so a sub-5-minute
result end-to-end (rule evaluation + Winlogbeat shipping + Elasticsearch
indexing) is a reasonable, credible number for this rule as configured.

**Unplanned finding while isolating this measurement:** searching the
Alerts index for this rule turned up 10+ pages of historical alerts, the
overwhelming majority *not* false positives in the usual sense, but
repeated alerts from earlier debugging sessions where
`Invoke-AtomicTest T1021.002 -TestNumbers 1` was run **without**
`-InputArgs`, defaulting to Atomic Red Team's literal placeholder values
(`net use \\Target\C$ P@ssw0rd1 /u:DOMAIN\Administrator`). Worth noting
as a genuine, useful detection property: **the rule fired correctly on
the process-creation attempt even though the underlying `net use`
command itself failed** (bad hostname) — process creation happens before
the network call resolves, so the rule detects the *attempt*
independent of success. Arguably more valuable for real detection than
requiring a successful connection, since a failed lateral-movement
attempt is still worth an analyst's attention.

This also means the rule currently has **no alert suppression
configured** (left optional at rule-creation time) — every placeholder
test run generated its own alert rather than being grouped. Worth
revisiting suppression settings before treating alert *volume* as a
meaningful metric in future, since right now volume reflects debugging
repetition, not real signal frequency.

### Alert volume, false positive rate, precision — not currently measurable

**Honestly: none of these can be meaningfully measured yet.** Every alert
in this lab so far has come from a deliberate, self-triggered test — there
is no real background traffic to generate false positives against, and a
false-positive rate calculated from zero real noise is not a real number.

This is stated explicitly rather than papered over with a fabricated
percentage. The false-positive sections in each rule's Detection Quality
write-up are labeled as *anticipated from technique knowledge*, not
observed — this metrics document inherits that same honesty.

## What would make these measurable

| Metric | What's needed to measure it for real |
|---|---|
| Clean detection latency | Re-run 2–3 existing atomic tests as isolated measurements, with no concurrent debugging work, and record trigger → alert timestamps precisely |
| Alert volume / FP rate / precision | Either (a) sustained benign activity on the lab VM over days/weeks to generate real background noise, or (b) HTB Active Machine sessions generating varied, non-scripted telemety the rules can be run against, reviewed for true/false positive classification |
| Broader coverage | Continue mapping toward uncovered tactics — Credential Access and genuine Discovery are the most natural next additions given the existing rule style |

## Status

- ✅ Coverage — measured, documented, honest about gaps
- ✅ Detection latency — clean, isolated measurement obtained (rule #11: ~3m49s); surfaced a real finding about alert suppression as a byproduct
- ⬜ Alert volume, false positive rate, precision — blocked on real/realistic traffic; not fabricated in the meantime

**This is the correct state for a lab-only project at this stage.** The
value of this document isn't the numbers it contains yet — it's
demonstrating the measurement methodology and being explicit about what
data would be needed to complete it, which is itself a detection
engineering skill worth showing.