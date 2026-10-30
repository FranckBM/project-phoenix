# Case study: logs that arrived perfectly and could not be detected on

**Pipeline:** AWS CloudTrail → S3 → SQS → Elastic Serverless Forwarder → Elasticsearch
**Found and fixed:** 2026-09-26
**Stack:** CloudTrail, Elastic Serverless Forwarder (Lambda), Elastic Security serverless, Fleet API

## Summary

My CloudTrail pipeline delivered 1,879 events into Elasticsearch with no errors anywhere. None of them could be detected on: each one was a single unparsed JSON string in a `message` field. The cause was an integration I believed was installed but never was. Nothing in the pipeline was broken; a step was missing, and nothing reports a missing step.

A second lesson came later, while writing this up. My notes said the data had been unparsed for "the better part of two weeks". The data says about 41 hours.

## What I thought I had

The AWS CloudTrail integration ships the ingest pipeline that turns raw CloudTrail JSON into structured fields such as `aws.cloudtrail.user_identity.type`, `event.action` and `event.provider`. I believed it was installed.

Weeks before building the pipeline, I had opened the integration in Kibana and started its setup wizard. The wizard's preferred deployment mode ("Elastic Managed Integration") was greyed out on this serverless project, so I cancelled it. Later I built the Lambda/SQS forwarder path by hand, assuming the integration itself was in place.

## What I actually had

Data flowed. The forwarder ran without errors, the data stream `logs-aws.cloudtrail-default` grew, and Discover showed new documents arriving. But:

| Check | Result |
|---|---|
| Field sidebar, filtered to `cloudtrail` | "No available fields" |
| Query `aws.cloudtrail.user_identity.type: *` | No results |
| Document contents | One raw JSON string in `message`, for example `{"eventVersion":"1.10","userIdentity":{"type":"IAMUser",...},"eventName":"ConsoleLogin",...}` |

A healthy-looking pipeline and an unusable data set at the same time.

## How it was found

While writing the first AWS rule (root account usage), I opened Discover expecting `aws.cloudtrail.user_identity.type`. It did not exist. The rule's whole condition depends on that field, so the rule could never have fired.

Two checks pinned down the cause:

1. **Stack Management → Ingest Pipelines:** empty. No CloudTrail pipeline existed.
2. **Integrations → Installed integrations:** six integrations were installed (Elastic Agent, Elastic Defend, Prebuilt Security Detection Rules, System, Windows, Zeek). AWS was not one of them.

## Root cause

In Kibana, browsing or configuring an integration and installing its package assets are separate steps. The assets (ingest pipelines, index templates) are installed as part of the wizard's flow, so cancelling the wizard left nothing installed. No message said so, and the wizard makes it feel as if you are doing the install the whole time.

Without the ingest pipeline, Elasticsearch did exactly what it should: it stored the forwarder's payload as text.

## Fix

I installed the package assets directly through the Fleet API, bypassing the wizard:

```powershell
Invoke-RestMethod -Uri "<kibana-url>/api/fleet/epm/packages/aws" `
    -Headers $headers -Method Post -Body '{"force": true}'
```

Then I verified each stage rather than assuming:

- **Ingest Pipelines:** a `logs-aws.cloudtrail-*` pipeline now existed.
- **Index template:** `logs-aws.cloudtrail` already had `index.default_pipeline` pointing at it, set by the package install. My first assumption, that I would need to edit the template by hand, was wrong.
- **Fresh event:** I generated new CloudTrail activity by clicking around IAM in the console. In Discover it arrived fully structured, with fields such as `aws.cloudtrail.user_identity.session_context.mfa_authenticated` and `aws.cloudtrail.read_only` present and typed.

## What the fix did not fix

An ingest pipeline only runs when a document is indexed. Everything that arrived before the fix stayed unparsed. I measured it on 2026-10-30, by counting documents in the data stream with no `aws.cloudtrail` fields:

| Item | Value |
|---|---|
| Unparsed documents still in the index | 1,879 |
| Earliest | 2026-09-24 17:43 UTC |
| Latest | 2026-09-26 10:59 UTC |
| Gap | about 41 hours |

These documents are still in the index and invisible to every rule. They were never reprocessed. Doing so is possible (for example `_update_by_query` through the pipeline), but no detections were running in that window, so the loss is a gap in history, not a missed alert.

## Memory versus measurement

My session notes from the day of the fix said the data had been flowing unparsed "for the better part of two weeks". I repeated that figure in the project roadmap. When I finally queried the index for this write-up, the gap was 41 hours.

The likely source of the error: the wizard was cancelled weeks earlier, but data only started flowing when the pipeline was built on 24 September. I remembered the age of the mistake, not the age of the data. The "two weeks" figure came from reasoning about when the problem began, not from the data.

The same project's metrics document refuses to claim false positive rates without real traffic. This was the same principle, applied to my own notes: an impact figure needs a query behind it.

## What I would do differently

- **Check for a known parsed field on day one.** One query on `event.action` or `aws.cloudtrail.user_identity.type` right after the first documents arrive would have caught this in minutes, not 41 hours.
- **Verify installation, not intent.** "I opened the integration" is not "the integration is installed". After any interrupted setup, check Installed integrations and Ingest Pipelines.
- **Treat "documents arriving" as a weak health signal.** Volume says the transport works. Only a parsed field says the data is usable.
- **Measure impact before writing it down.** Count the affected documents and their time range at the time of the fix.

## Limits of this evidence

- One pipeline, one cloud account, one person. I have not tested whether other integrations behave the same way after a cancelled wizard.
- The gap is measured from the documents' `@timestamp` values, which for unparsed documents most likely reflect ingest time rather than event time. Either way, they bound when the pipeline was delivering without parsing.

## Takeaways

1. A pipeline can be healthy and its data unusable. Delivery and parsing are separate properties, and only the second matters for detection.
2. Missing steps fail silently. Look for evidence that each stage happened, not just for errors.
3. Fixing ingest does not fix history. Every parsing fix needs a decision about the data that landed before it.
4. Quantify impact from the data, not from memory, including your own notes.