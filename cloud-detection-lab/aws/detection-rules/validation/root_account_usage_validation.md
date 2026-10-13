Root Account Usage — Validated
Summary

Closed the one open item on the AWS root account detection: a real, deliberate root-login test, confirming the rule fires correctly and the earlier zero-false-positive baseline holds.

Test method

Logged into the AWS console as the root user (not an IAM user) via an incognito browser window, to keep the normal working IAM session untouched. Browsed the console homepage briefly — enough to generate background API activity from the various dashboard widgets (Cost Explorer, IAM, Free Tier, Billing, Health, etc.) — then signed out of the root session immediately afterward.

Result

128 documents matched aws.cloudtrail.user_identity.type: "Root" in the 15-minute window around the test, tightly clustered between 15:34–15:36, exactly matching the actual login/browsing window. Confirmed via cloud.service.name field distribution that the activity was legitimate console-load noise (ce 27.3%, iam 14.8%, freetier 10.9%, bcm-recommended-actions 9.4%, health 7.0%, and smaller shares across cost-optimization-hub, payments, budgets, account, access-analyzer) — consistent with a single root console login populating its dashboard widgets, not anything anomalous.

What this confirms
Detection logic is correct: the rule's single condition (aws.cloudtrail.user_identity.type: 'Root') cleanly isolates root-attributed events from the surrounding IAMUser/AssumedRole/AWSService noise
Pipeline captures root activity correctly end-to-end: CloudTrail → S3 → SQS → Elastic Serverless Forwarder → Elasticsearch → parsed, queryable field — no gaps in the chain for this event type
Baseline still holds: prior to this test, root usage was 0% of all CloudTrail activity (checked across IAMUser 84.1% / AWSService 9.5% / AssumedRole 6.3%). This test event is now the only root activity in the account's CloudTrail history — exactly the rarity this rule is designed to catch
Volume note worth keeping in mind for future tuning: a single root login can generate 100+ individual CloudTrail events from one console session (dashboard widgets each firing their own API calls). If this rule is ever wired to a live Kibana alert with per-event alerting (rather than aggregated), it would produce a burst of alerts for one real login event — worth considering alert suppression/grouping by session or time window if this moves from Sigma-source-only to an actual running Kibana rule, same lesson learned from the Windows SMB Admin Share rule's missing suppression
Status

AWS Root Account Usage Detected (T1078.004) — fully validated: written, baseline-confirmed, and now trigger-confirmed. First complete cloud detection in the portfolio, matching the same validation rigor applied to the 11 Windows rules.

Outstanding backlog
 Import this rule into Kibana as a live Detection Engine rule (currently Sigma source + Discover-validated only, same state the Windows rules were in before API/UI import)
 Consider alert suppression/grouping before going live, given the 128-events-per-login volume pattern observed here
 IAM policy change detection (next cloud rule candidate)
 Azure Entra ID detections, identity folded into this same lab
 ## Live rule validation (Kibana Detection Engine)

**Date:** 2026-10-13

The rule was imported into Kibana as a Custom query rule and enabled.

| Setting | Value |
|---|---|
| Index pattern | `logs-aws.cloudtrail-*` |
| Query (KQL) | `aws.cloudtrail.user_identity.type : "Root"` |
| Severity / risk score | High / 73 |
| ATT&CK | T1078.004 (Initial Access) |
| Schedule | every 5 minutes, 4 minute additional look-back |
| Alert suppression | by `aws.cloudtrail.user_identity.arn`, per time period, 1 hour |
| Missing suppression field | do not suppress (a root event is never hidden) |

**Test:** one root console login.

**Result:** 1 alert created, with 28 further alerts suppressed into it (29 matching events in total). The alert had category `authentication` and fired within the rule's schedule window.

**Finding confirmed:** without suppression, one root login would have created dozens of near-identical alerts. The 1-hour suppression window turns one session into one alert while a second root login later the same day still alerts.

**Not measured:**
- Detection latency (root login time to alert) was not captured, so no figure is claimed.
- False positive rate and alert volume remain unmeasured; they are blocked on real traffic.

**Rule preview note:** the Kibana preview timed out over a 30-day range. It replays the rule every 5 minutes, so that is expected and not a rule problem. The query was validated in Discover and by the live test above.