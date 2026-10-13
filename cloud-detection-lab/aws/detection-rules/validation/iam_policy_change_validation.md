# Validation: AWS IAM Policy Created, Attached or Modified

- **Rule:** `aws_iam_policy_change.yml` (id `ba56ad2a-4c43-4d9d-b933-db8d42bceb44`)
- **ATT&CK:** T1098.003 (Account Manipulation: Additional Cloud Roles)
- **Date validated:** 2026-10-09
- **Data source:** CloudTrail management events -> S3 -> SQS -> Elastic Serverless Forwarder -> `logs-aws.cloudtrail-default`

## 1. Field verification

The rule uses `event.provider` and `event.action`. These were assumed from the ECS-style mapping, so they were checked against real parsed documents before the trigger test.

| Rule field | Raw CloudTrail field | Result |
|---|---|---|
| `event.provider` | `eventSource` | Confirmed: matched `iam.amazonaws.com` |
| `event.action` | `eventName` | Confirmed: matched `CreatePolicy` |

Other fields seen on the parsed documents: `aws.cloudtrail.user_identity.type`, `aws.cloudtrail.flattened.response_elements` (carries the new policy ARN).

## 2. Trigger test

Action performed in the AWS console as an IAM user:

1. IAM -> Policies -> Create policy (JSON editor).
2. Policy: single statement allowing `s3:ListAllMyBuckets` on `*`. Harmless and not attached to any identity.
3. Name: `phoenix-test-policy`. Created at 2026-10-09T15:34:39Z.
4. Policy deleted immediately afterwards.

Query in Discover (`logs-aws.cloudtrail-*`):

```
event.provider: "iam.amazonaws.com" and event.action: "CreatePolicy"
```

**Result:** 1 event returned, matching the created policy. The response elements contain the new policy ARN (`arn:aws:iam::<ACCOUNT_ID>:policy/phoenix-test-policy`).

## 3. Expected non-match

`DeletePolicy` is deliberately not in the rule's action list. Removing a policy does not grant access, so it should not alert.

## 4. Not yet tested

- The rule has not been imported into Kibana as a live Detection Engine rule, so alert generation is not yet validated, only the query logic.
- The other actions in the list (`Attach*Policy`, `Put*Policy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`) were not individually triggered. They share the same field mapping, so risk is low, but they are unverified.
- False positive rate and alert volume are not measured. They are blocked on real traffic, and no figures are claimed here.

## 5. Tuning notes

- One console action can produce several CloudTrail events, so alert suppression is needed. Suggested: suppress by `aws.cloudtrail.user_identity.arn` over 1 hour.
- Expected false positives: administrators and infrastructure-as-code pipelines making planned permission changes. Exclude known automation roles once they are identified in real data.
- Severity is medium. Raise it where the actor is a root user, an identity with no MFA, or a policy granting `*:*`.

## 6. Redaction

Account ID, access key IDs and source IPs are removed from this document. Do not paste raw `event.original` into the public repo.