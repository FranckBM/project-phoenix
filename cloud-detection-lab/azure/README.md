# Cloud Detection Lab — Azure (Entra ID)

The Azure half of the Cloud Detection Lab. Same approach as the AWS side:
build the pipeline, test detections against real tenant activity, and record
the gotchas rather than hiding them.

## Structure

```
azure/
  ingest_entra_audit.py        # Microsoft Graph audit logs -> Elasticsearch
  config.yaml.template         # Placeholder values only (real config.yaml is gitignored)
  detection-rules/
    sigma/                     # Sigma rules for Entra ID audit detections
    validation/                # Live test evidence per rule
```

## Pipeline

**Flow:** Entra ID audit logs → Microsoft Graph (`/auditLogs/directoryAudits`)
→ `ingest_entra_audit.py` (polling) → Elasticsearch data stream
`logs-azure.entra_audit-default`

Chosen over the Event Hub route, which was rejected for cost and complexity in
a personal lab.

### Setup summary

1. **Tenant** — a dedicated Microsoft Entra ID **Free** tenant with a cost
   budget alert and test users.
2. **App registration** — `phoenix-audit-reader`, Microsoft Graph
   **Application** permission `AuditLog.Read.All` (admin consent granted),
   client-secret authentication. Read-only by design.
3. **Ingest script** — `ingest_entra_audit.py`:
   - pages through `/auditLogs/directoryAudits` from a saved watermark
     (`state.json`)
   - re-reads a 15-minute overlap on every poll, so late-arriving events are
     not missed
   - uses the Entra event id as the Elasticsearch `_id`, so overlapping polls
     never create duplicates (`already_present` in the output)
   - maps key fields to ECS (`event.action`, `event.outcome`, `user.name`)
     and keeps the raw Graph record under `entra.audit.*`
   - runs once by default, or continuously with `--loop SECONDS`
     (the lab uses `--loop 120`)

```
python ingest_entra_audit.py              # single run
python ingest_entra_audit.py --loop 120   # poll every 2 minutes
```

### Secrets handling

The real `config.yaml` (tenant ID, client ID, client secret, Elasticsearch
endpoint, API key) and `state.json` are **gitignored**. Only
`config.yaml.template`, with placeholder values, is committed.

## Detections

| # | Rule | ATT&CK | Status | Validation |
|---|---|---|---|---|
| 1 | Entra ID Application Credentials Changed | T1098.001 | ✅ Live in Kibana, suppression by `user.name` (1h). ~5m32s event to alert. Credential removals also match | [validation](detection-rules/validation/Entra_app_credential_change_validation.md) |
| 2 | Entra ID Directory Role Assigned to User | T1098.003 | ✅ Live in Kibana, no suppression by design. ~4m00s event to alert. Role removal correctly did not alert | [validation](detection-rules/validation/role_assignment_validation.md) |

Latency figures are single observations. Event-to-ingest is Graph availability
plus up to 120 s of polling; ingest-to-alert depends on where the event lands
in the 5-minute rule schedule.

## Gotchas and limits

**1. A Free tenant cannot export sign-in logs.** Exporting sign-in logs needs
Entra ID P1 or P2, so this lab runs on **audit logs only**. Sign-in based
detections (impossible travel, MFA fatigue, risky sign-ins) are out of scope
unless a P1/P2 trial is added.

**2. Wildcards on `modifiedProperties.newValue` returned nothing.** A filter
meant to separate credential additions from removals matched nothing, even
though the field was populated. Exact `term` queries on the same field do work
(including its literal double quotes, e.g. `"\"Security Reader\""`). The
working theory is that long values exceed the keyword `ignore_above` limit and
are stored in `_source` but never indexed; this is not yet confirmed, because
the mapping API is unavailable on Elastic serverless.

**3. Audit log retention limits downtime.** The script catches up from its
watermark, but only within the tenant's audit log retention (short on the
Free tier). If ingest is stopped for longer than that, events are lost.

**4. Directory vs app-scoped roles.** An app registration's own "Roles and
administrators" page assigns roles scoped to that app only. The role
assignment rule was tested with a **directory-level** assignment.

## Next steps

- High-severity variant of the role assignment rule, scoped to privileged
  role template IDs (Global Administrator, Privileged Role Administrator, etc.)
- Service principal creation detection (Microsoft first-party provisioning is
  already visible in the baseline as noise to account for)
- Sign-in based rules only with a P1/P2 trial