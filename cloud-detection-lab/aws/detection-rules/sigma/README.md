# Cloud Detection Lab

Extension of Project Phoenix into cloud telemetry — AWS first, Azure Entra ID
planned next. Same philosophy as the Windows lab: build the pipeline, break
it, fix it, document the real gotchas, then write detections against real
data rather than assumptions.

## Structure

```
cloud-detection-lab/
  aws/
    config.yaml.template       # Elastic Serverless Forwarder config (placeholder values — see below)
    detection-rules/
      sigma/                   # Sigma rules for AWS CloudTrail detections
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

## Detections

| Rule | ATT&CK Technique | Status |
|---|---|---|
| AWS Root Account Usage Detected | T1078.004 | Built, validated with zero false-positive baseline (0 root events in normal account activity) |

## Next steps

- Validate the root-account rule with a real, deliberate root-login test event
- IAM policy change detection
- Azure Entra ID detections (suspicious auth, privilege/role assignment)
- Fold identity detections into this lab rather than treating them as a separate project