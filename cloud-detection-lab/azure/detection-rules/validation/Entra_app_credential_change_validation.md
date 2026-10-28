# Validation: Entra ID Application Credentials Changed

- **Rule:** `azure_entra_app_credential_changed.yml` (id `f97a3276-c7fa-421a-b4eb-3a193d17edcf`)
- **ATT&CK:** T1098.001 (Account Manipulation: Additional Cloud Credentials), Persistence
- **Date validated:** 2026-10-22
- **Data source:** Microsoft Entra ID audit logs -> Microsoft Graph (`/auditLogs/directoryAudits`) -> `ingest_entra_audit.py` (polling) -> `logs-azure.entra_audit-default`

Entra ID Free tenant. Sign-in log export needs a P1 or P2 licence, so this lab is built on audit logs only.

## 1. Field verification

Checked on real documents before the rule was written.

| Rule field | Value seen | Note |
|---|---|---|
| `event.provider` | `azure.entra` | Set by the ingest script, not by Microsoft |
| `entra.audit.category` | `ApplicationManagement` | Raw Graph field `category` |
| `event.action` | `Update application – Certificates and secrets management` | Raw Graph `activityDisplayName`. Contains an en dash, so the rule matches on the shorter text `Certificates and secrets management` |
| `event.outcome` | `success` | Derived by the script from Graph `result` |

Other fields seen: `user.name` (the initiating user), `entra.audit.targetResources.displayName` (the application), `entra.audit.targetResources.modifiedProperties.newValue` (carries `KeyType=Password` on a secret addition).

## 2. Baseline

Before the rule existed, the data stream held 3 events. One matched the rule: the creation of the audit reader app's own client secret on 2026-10-20. This is lab setup activity, not a measured false positive rate.

## 3. Live rule settings (Kibana Detection Engine)

| Setting | Value |
|---|---|
| Index pattern | `logs-azure.entra_audit-*` |
| Query (KQL) | `event.provider : "azure.entra" and entra.audit.category : "ApplicationManagement" and event.action : *secrets*management* and event.outcome : "success"` |
| Severity / risk score | Medium / 47 |
| ATT&CK | T1098.001 (Persistence) |
| Schedule | every 5 minutes, additional look-back 15 minutes |
| Alert suppression | by `user.name`, per time period, 1 hour |

## 4. Finding: a filter on the modified property value did not work

The first design also required the credential to be present after the change, using the `newValue` field (a real addition shows `KeyType=Password` there). Results in Discover on the real event:

| Query on `entra.audit.targetResources.modifiedProperties.newValue` | Result |
|---|---|
| `: *KeyType*` | no hits |
| `: *keytype*` | no hits |
| `: *` | all 3 documents |

The field exists, is populated and is shown as a keyword, but wildcard searches on its contents return nothing. The cause was not found. The clause was dropped, so the rule cannot tell a credential addition from a removal. Both use the same activity name.

## 5. Live test

Action: a throwaway client secret was added to the audit reader app registration in the Entra portal. The ingest script was running in loop mode (every 120 seconds).

Result: the rule alerted. `kibana.alert.suppression.docs_count` was 0, as expected for a single event.

**Detection latency (single run, 2026-10-22, local time UTC+1):**

| Stage | From | To | Duration |
|---|---|---|---|
| Graph availability plus polling | Entra event time 12:03:38 (`activityDateTime` 11:03:38Z) | ingested 12:05:57 (`event.created`) | 2m18s |
| Rule schedule | ingested 12:05:57 | alert 12:09:10 | 3m13s |
| **End to end** | event 12:03:38 | alert 12:09:10 | **5m32s** |

The first stage combines the time Graph took to expose the event with the 120 second polling interval, and the two cannot be separated from this run.

**Removal test (same day):** the throwaway secret was then deleted (event at 12:30:58 local time). No new alert row appeared. Because the rule suppresses by `user.name` for 1 hour, the event was added to the existing alert: `kibana.alert.suppression.docs_count` rose from 0 to 1, with the suppression window running from 12:03:38 (the addition) to 12:30:58 (the removal). So a removal matches the rule, as predicted from section 4, and the alert does not say which kind of change it was.

## 6. Not yet tested

- Credential removal: confirmed to match the rule (see section 5), so additions and removals are not separated. Removal was tested only once, as the last of two credentials changes by the same user within the suppression hour.
- Credentials added directly to a service principal (rather than the application object) are a different operation and were not tested.
- Certificates (as opposed to client secrets) were not tested.
- No role-assignment rule exists yet; that event was never generated in this lab.
- If the ingest script is not running, no data arrives and no alerts fire. In this lab the script is run by hand.
- False positive rate and alert volume are not measured. No figures are claimed.
- Latency was observed once, so it is a single observation, not a distribution.

## 7. Tuning notes

- Expected false positives: planned secret rotation by application owners and deployment pipelines. Exclude known owners once identified in real data.
- Suppression by user for 1 hour folds a later change by the same user into the first alert, as the removal test showed. An analyst should check the alert's suppressed document count and window, not just the first event.
- Severity is medium. Raise it where the application holds high Graph permissions or the initiator is not the application's owner.
- Keep the additional look-back above the polling interval plus the observed Graph delay. 15 minutes is generous against the 2m18s observed, but one observation does not prove a worst case.

## 8. Redaction

Tenant ID, client ID, client secret, user object IDs, the initiating user's email address and public IP address are removed from this document. Do not paste raw audit documents or unredacted screenshots into the public repo.