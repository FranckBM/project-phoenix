# Cloud Detection Lab — AWS (CloudTrail)

The AWS half of the Cloud Detection Lab (the Azure Entra ID half is in
[`../azure/`](../azure/README.md)). Same philosophy as the Windows lab: build
the pipeline, break it, fix it, document the real gotchas, then write
detections against real data rather than assumptions.

## Structure

```
aws/
  config.yaml.template         # Elastic Serverless Forwarder config (placeholder values — see below)
  detection-rules/
    sigma/                     # Sigma rules for AWS CloudTrail detections
    validation/                # Live test evidence per rule
```

## AWS pipeline

**Flow:** CloudTrail → S3 → SQS → Elastic Serverless Forwarder (Lambda) → Elasticsearch

Chosen deliberately over an Elastic Agent/Fleet-based collector, for two
reasons: it's event-driven with no persistent compute to babysit (more
cloud-native than running an agent on a VM), and Fleet had already caused
real instability on the Windows lab side, so avoiding it here was a
conscious call, not an oversight.

### Setup summary

1. **CloudTrail** — single multi-region trail, management events only
   (read + write). Data events deliberately left off — that's the one that
   gets expensive fast, and isn't needed for the detections planned so far.
2. **S3** — CloudTrail's default log bucket. A *separate*, small bucket
   holds `config.yaml` for the forwarder, kept apart from the CloudTrail
   bucket specifically to avoid the config upload itself triggering a
   spurious S3 event notification.
3. **SQS** — a standard queue, 910s visibility timeout (Elastic's own
   recommendation), subscribed to the CloudTrail bucket's
   `s3:ObjectCreated:*` event notifications.
4. **Elastic Serverless Forwarder** — deployed via the AWS Serverless
   Application Repository. Reads `config.yaml` from S3, triggered by the
   SQS queue, ships parsed events to Elasticsearch.
5. **AWS integration package** — installed directly via the Fleet API
   (`POST /api/fleet/epm/packages/aws`), not through the standard "Add
   integration" UI wizard. This provisions the ingest pipeline
   (`logs-aws.cloudtrail-*`) that structures raw CloudTrail JSON into
   queryable fields like `aws.cloudtrail.user_identity.type`.

### Secrets handling

The real `config.yaml` (containing the actual Elasticsearch URL and API
key) is **gitignored** and lives only on the local machine — see
`.gitignore` at the repo root. `config.yaml.template` is committed with
fully placeholder'd values instead. Never commit the real file.

## Gotchas found building this pipeline

**1. "Elastic Managed Integration" deployment mode was greyed out.**
Kibana's guided AWS integration setup offers a simpler mode where Elastic
hosts the polling for you — unavailable for this serverless project.
Forced the manual Lambda/SQS deployment path instead, which turned out to
be the better pattern anyway (event-driven, no persistent agent).

**2. `403 Forbidden` on S3 `GetObject`, despite the SQS trigger working
correctly.** The Lambda's `ElasticServerlessForwarderS3SQSEvents`
CloudFormation parameter wires up the *event trigger* (permission to
consume from SQS) — it does **not** separately grant `s3:GetObject` on the
bucket holding the actual CloudTrail files. A second, easily-missed
parameter, `ElasticServerlessForwarderS3Buckets`, is required for that.
Fixed via a CloudFormation stack update once identified from the Lambda's
CloudWatch Logs traceback.

**3. Installing an integration ≠ configuring it through the wizard.**
Clicking into the AWS CloudTrail integration and cancelling out of its
agent-deployment wizard (after hitting gotcha #1) does **not** install the
package's underlying assets (ingest pipeline, index templates) — those are
two separate steps in Kibana's model. Result: CloudTrail data flowed into
Elasticsearch successfully for days, but sat entirely unparsed inside a
raw `message` string, since no ingest pipeline existed to structure it.
Diagnosed by checking **Stack Management → Ingest Pipelines** (empty) and
**Installed Integrations** (AWS CloudTrail absent from the list, despite
having "used" it in the wizard). Fixed by installing the package assets
directly via the Fleet API, bypassing the wizard entirely:
```powershell
Invoke-RestMethod -Uri "<kibana-url>/api/fleet/epm/packages/aws" `
    -Headers $headers -Method Post -Body '{"force": true}'
```
Note this also matters for timing: the ingest pipeline only applies to
documents indexed *after* it exists. Data ingested before the fix stays
unparsed permanently unless manually reprocessed.

**4. CloudTrail delivery can outrun a rule's look-back window.** The first
live test of the no-MFA rule missed: CloudTrail took about 5 minutes to
deliver the login event, longer than the rule's 4-minute look-back, so the
event was indexed after the window that should have caught it had already
run. The rule logic was correct; the timing was not. Look-back was raised to
10 minutes on all three rules. Written up as a case study:
[A correct rule that missed its own test](../../writeups/case-study-cloudtrail-delivery-vs-rule-lookback.md).

## Detections

All three rules are live in Kibana as Detection Engine rules (5-minute
schedule, 10-minute look-back), with alert suppression by
`aws.cloudtrail.user_identity.arn` for 1 hour, and validated end to end
against real CloudTrail data.

| # | Rule | ATT&CK | Severity | Live test | Validation |
|---|---|---|---|---|---|
| 1 | AWS Root Account Usage | T1078.004 | High / 73 | 0 root events in the baseline; one root console session gave 1 alert with 28 suppressed (29 events) | [validation](detection-rules/validation/root_account_usage_validation.md) |
| 2 | AWS IAM Policy Created, Attached or Modified | T1098.003 | Medium / 47 | A harmless `CreatePolicy` gave 1 alert, ~7m35s event to alert | [validation](detection-rules/validation/iam_policy_change_validation.md) |
| 3 | AWS Console Login Without MFA | T1078.004 | Medium / 47 | Successful IAM user login without MFA gave 1 alert, ~6m44s event to alert; a login with MFA correctly did not alert | [validation](detection-rules/validation/aws_console_login_no_mfa_validation.md) |

Latency figures are single observations. CloudTrail delivery and ingest alone
varied between about 2m36s and 5m06s, on top of the 5-minute rule schedule.

## Cost

Management events only, low-volume S3/SQS/Lambda usage: expected to stay
near $0/month, with AWS budget alerts as a safety net.

## Next steps

- More AWS detections as time allows (for example access key creation,
  CloudTrail tampering)
- Optionally reprocess the ~41 hours (1,879 documents) of CloudTrail data
  that landed unparsed before gotcha #3 was fixed