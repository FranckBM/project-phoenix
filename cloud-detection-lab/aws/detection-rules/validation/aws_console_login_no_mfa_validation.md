# Validation: AWS Console Login Without MFA

- **Rule:** `aws_console_login_no_mfa.yml` (id `3f6b1c52-8d0a-4e57-9a1e-6c2d7b94f0a3`)
- **ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts), Initial Access
- **Date validated:** 2026-10-14
- **Data source:** CloudTrail management events -> S3 -> SQS -> Elastic Serverless Forwarder -> `logs-aws.cloudtrail-default`

## 1. Field verification

The rule matches on parsed ECS-style fields. These were checked on a real `ConsoleLogin` document before the rule was written.

| Rule field | Value seen | Note |
|---|---|---|
| `event.provider` | `signin.amazonaws.com` | Console sign-in service |
| `event.action` | `ConsoleLogin` | |
| `event.outcome` | `success` | Rule alerts on successful logins only |
| `aws.cloudtrail.user_identity.type` | `IAMUser` | Rule is scoped to IAM users |
| `aws.cloudtrail.console_login.additional_eventdata.mfa_used` | `false` (boolean) | The MFA flag. Raw CloudTrail name is `additionalEventData.MFAUsed` |

## 2. Baseline (30 days, before the rule existed)

Query in Discover on `logs-aws.cloudtrail-*`:

```
event.provider : "signin.amazonaws.com" and event.action : "ConsoleLogin" and event.outcome : "success" and aws.cloudtrail.user_identity.type : "IAMUser" and aws.cloudtrail.console_login.additional_eventdata.mfa_used : false
```

**Result:** 9 events in 30 days, all from the same identity (`user/AWSAdmin`, the only active IAM user in this lab). This is a measured baseline for a one-person lab, not a false positive rate and not representative of a real environment.

## 3. Live rule settings (Kibana Detection Engine)

| Setting | Value |
|---|---|
| Index pattern | `logs-aws.cloudtrail-*` |
| Query (KQL) | `event.provider : "signin.amazonaws.com" and event.action : "ConsoleLogin" and event.outcome : "success" and aws.cloudtrail.user_identity.type : "IAMUser" and aws.cloudtrail.console_login.additional_eventdata.mfa_used : false` |
| Severity / risk score | Medium / 47 |
| ATT&CK | T1078.004 (Initial Access) |
| Schedule | every 5 minutes |
| Additional look-back | 4 minutes at creation, **changed to 10 minutes** after test 1 (see below) |
| Alert suppression | by `aws.cloudtrail.user_identity.arn`, per time period, 1 hour |

## 4. Test 1: login missed (look-back too short)

The rule was created at 16:38. A console login without MFA was made at 16:39 as `AWSAdmin`. **No alert fired.**

| Item | Time |
|---|---|
| Event `@timestamp` | 16:39:14 |
| `event.created` (ingested) | 16:44:20 (delivery and ingest took 5m06s) |
| Run before ingest | ~16:43:20 (event not yet in the index) |
| Run after ingest | ~16:48:20, window start ~16:39:20 |

The event arrived after one run and was already older than the next run's window (4 minute look-back plus the 5 minute interval, about 9 minutes), by about 6 seconds. The rule filters on `@timestamp`, which is the CloudTrail event time, so a delivery delay near 5 minutes can push an event out of the window before any run sees it. The rule logic itself was correct.

**Fix:** additional look-back raised from 4 to 10 minutes. Overlapping windows are safe because alert suppression collapses repeats.

**Implication:** the two earlier AWS rules were created with the same 4 minute look-back and have the same exposure. Raise them too.

## 5. Test 2: login alerted

With the 10 minute look-back, a console login without MFA at about 16:59 as `AWSAdmin` produced one alert.

**Result:** 1 Medium alert (risk score 47) for `AWSAdmin`. `kibana.alert.suppression.docs_count` was 0, as expected for a single event.

**Detection latency (single run, 2026-10-14):**

| Stage | From | To | Duration |
|---|---|---|---|
| CloudTrail delivery and ingest pipeline | event `@timestamp` 16:59:03 | `event.created` 17:04:09 | 5m06s |
| Rule schedule | `event.created` 17:04:09 | alert 17:05:47 | 1m38s |
| **End to end** | event `@timestamp` 16:59:03 | alert 17:05:47 | **6m44s** |

The ingest stage has now been observed three times on this rule: 5m06s (test 1), 5m06s (test 2) and 4m58s (test 3 below). The IAM rule's test on 2026-10-13 took 2m36s. Delivery time varies, so end-to-end latency is an observation per run, not a fixed figure. The rule stage depends on where the 5 minute schedule falls.

## 6. Test 3: non-match with MFA

MFA was enabled on `AWSAdmin`, then a console login was made with MFA at 17:21:00.

- The event arrived with `mfa_used : true` (`event.created` 17:25:58, delivery and ingest 4m58s).
- Rule runs after ingestion: 17:30:26 and 17:35:26.
- **Result:** no new alert. The Alerts page still showed only the single alert from test 2.

## 7. Not yet tested

- Logins by users other than `AWSAdmin`.
- Federated or SSO logins are out of scope: they can show `mfa_used: false` even when MFA happened at the identity provider, so the rule only matches `IAMUser`. Whether real federated traffic would also be worth detecting is not tested.
- Root logins without MFA are not handled by this rule (the root usage rule covers any root activity).
- Failed logins are deliberately excluded (`event.outcome: success`). Repeated failures are a separate detection.
- False positive rate and alert volume are not measured. The 30 day baseline is 9 events from one identity, which says nothing about a production environment. No figures are claimed.
- Latency has been observed on a handful of runs, so it is not a distribution.

## 8. Tuning notes

- Expected false positives in a real environment: break-glass or legacy IAM users without a registered MFA device. These should be rare and documented. Exclude known identities by ARN once identified in real data.
- In this lab the rule alerted because `AWSAdmin` had no MFA. Enabling MFA on that user is the remediation the rule points to.
- Severity is medium. Raise it where the identity has administrator permissions or the login comes from an unexpected source.
- Keep the additional look-back at 10 minutes or more while CloudTrail delivery stays near 5 minutes.

## 9. Redaction

Account ID, source IPs, access key IDs and personal email addresses are removed from this document. Do not paste raw `event.original` or unredacted alert screenshots into the public repo.