# Case study: a correct rule that missed its own test

**Detection:** AWS Console Login Without MFA (T1078.004)
**Date:** 2026-10-14
**Stack:** CloudTrail, S3, SQS, Elastic Serverless Forwarder, Elastic Security (Detection Engine custom query rules)

## Summary

I built a detection, validated its query against 30 days of real data, enabled it, and ran a live test. The test login did not alert. The query was right. The rule's time window was too short for the way CloudTrail delivers events. I fixed the window on all three AWS rules and recorded the failure in the validation docs rather than dropping it.

## The rule

The rule alerts on a successful console login by an IAM user where CloudTrail reports `mfa_used: false`. Before enabling it I checked each field against a real `ConsoleLogin` document, then ran the query over 30 days: 9 events, all from the one IAM user in the lab. That baseline says the query works. It says nothing about false positive rates in a real environment.

Live settings: runs every 5 minutes, additional look-back 4 minutes, alert suppression by user ARN for 1 hour.

## What happened

I created the rule at 16:38 and logged in without MFA at 16:39. No alert fired.

The event was in the index and the query matched it, so the rule logic was not the problem. The remaining difference between "Discover finds it" and "the rule finds it" is time.

## Root cause

A Detection Engine rule does not search all of history. Each run searches a window: the rule interval plus the additional look-back. Here that was 5 + 4 = 9 minutes. The rule also filters on `@timestamp`, which for CloudTrail is the time the event happened, not the time it reached Elasticsearch.

| Item | Time |
|---|---|
| Event `@timestamp` | 16:39:14 |
| Event ingested (`event.created`) | 16:44:20 |
| Delivery and ingest delay | 5m06s |
| Last run before ingest | about 16:43:20 (event not in the index yet) |
| First run after ingest | about 16:48:20 |
| That run's window start | about 16:39:20 |

The event reached the index after one run and was about 6 seconds too old for the next run's window. No run ever saw it.

Put generally: when a run's window reaches back interval + look-back, an event is only guaranteed to be caught if its delivery delay is no more than the look-back. CloudTrail delivery took about 5 minutes here, and the look-back was 4. This is my reading of the window arithmetic. The test confirms it for one event; I did not test other delays.

## Fix

I raised the additional look-back from 4 to 10 minutes. Overlapping windows mean a run can see events an earlier run already saw. Alert suppression handles that: repeats collapse into the existing alert instead of creating new ones.

I then repeated the test:

| Stage | From | To | Duration |
|---|---|---|---|
| Delivery and ingest | event 16:59:03 | ingested 17:04:09 | 5m06s |
| Rule schedule | ingested 17:04:09 | alert 17:05:47 | 1m38s |
| End to end | event 16:59:03 | alert 17:05:47 | 6m44s |

The delivery delay was 5m06s again, which would have missed under the old setting. The rule alerted. I also logged in with MFA enabled (event 17:21:00) and confirmed no new alert, so the fix did not make the rule fire on logins it should ignore.

## The wider exposure

The two earlier AWS rules (root account usage and IAM policy changes) had been created with the same 4 minute look-back. Their live tests passed, but the IAM test happened to have a short delivery delay (2m36s), which sat inside the window. That was luck, not design. I raised both to 10 minutes and noted in their validation docs that earlier tests ran on the old setting and were not repeated.

I have no evidence that either rule missed a real event. The exposure existed and I closed it.

## What I would do differently

- Measure delivery delay before choosing a look-back. I set 4 minutes at creation without measuring how long CloudTrail takes to arrive. The check is a single Discover query comparing `@timestamp` with `event.created`.
- Treat "live test alerted" as the validation step, not "query returned results". A query-level check cannot catch a window problem.
- Test every new rule once through the full pipeline before trusting it.


## Limits of this evidence

- Delivery delay was observed on four runs: 2m36s (IAM rule) and 5m06s, 5m06s, 4m58s (this rule). That is a handful of observations, not a distribution. A delay longer than 10 minutes would still be missed.
- Latency figures are single runs, not averages.
- This is a one-person lab. Alert volume and false positive rate are not measured and no figures are claimed.

## Takeaways

1. A detection can be logically correct and still fail operationally. Query validation and rule validation are separate steps.
2. For cloud log sources, event time and arrival time differ, and the gap is part of the detection design.
3. Keep failed tests in the record. The missed alert is the most useful result in this project, because it led to a fix on all three live AWS rules.