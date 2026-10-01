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