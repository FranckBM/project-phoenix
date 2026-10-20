#!/usr/bin/env python3
"""Pull Microsoft Entra ID audit logs from Microsoft Graph and index them into Elasticsearch.

Reads /auditLogs/directoryAudits with an app registration (client credentials) and
bulk-indexes each event into a data stream. Documents use the Graph event id as the
Elasticsearch _id, so overlapping polling windows never create duplicates.

Config: config.yaml next to this script (gitignored). See config.yaml.template.
State:  state.json next to this script (gitignored). Holds the polling watermark.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

HERE = Path(__file__).resolve().parent
GRAPH_URL = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_ts(value):
    # Graph returns e.g. 2026-10-19T11:02:03.1234567Z (7 fractional digits)
    value = value.rstrip("Z")
    if "." in value:
        head, frac = value.split(".")
        value = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


def load_config(path):
    cfg = yaml.safe_load(Path(path).read_text())
    required = ["tenant_id", "client_id", "client_secret", "elastic_url", "elastic_api_key"]
    missing = [k for k in required if not cfg.get(k) or str(cfg[k]).startswith("<")]
    if missing:
        sys.exit(f"config.yaml is missing real values for: {', '.join(missing)}")
    cfg.setdefault("data_stream", "logs-azure.entra_audit-default")
    cfg.setdefault("lookback_minutes", 15)
    cfg.setdefault("first_run_hours", 24)
    return cfg


def get_token(cfg):
    resp = requests.post(
        TOKEN_URL.format(tenant=cfg["tenant_id"]),
        data={
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def fetch_events(token, since):
    """Yield raw directoryAudits events with activityDateTime >= since."""
    params = {"$filter": f"activityDateTime ge {iso(since)}", "$top": "100"}
    url = GRAPH_URL
    headers = {"Authorization": f"Bearer {token}"}
    while url:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("Retry-After", "10")))
            continue
        resp.raise_for_status()
        body = resp.json()
        yield from body.get("value", [])
        url = body.get("@odata.nextLink")
        params = None  # nextLink already carries the query


def transform(event, ingested_at):
    """Raw Graph event -> Elasticsearch document (ECS-style core fields + raw payload)."""
    initiator = event.get("initiatedBy") or {}
    init_user = initiator.get("user") or {}
    init_app = initiator.get("app") or {}
    result = (event.get("result") or "").lower()
    doc = {
        "@timestamp": iso(parse_ts(event["activityDateTime"])),
        "event": {
            "kind": "event",
            "provider": "azure.entra",
            "dataset": "azure.entra_audit",
            "category": ["iam"],
            "action": event.get("activityDisplayName"),
            "outcome": "success" if result == "success" else ("failure" if result else "unknown"),
            "created": iso(ingested_at),
        },
        "entra": {"audit": event},
    }
    name = init_user.get("userPrincipalName") or init_app.get("displayName")
    if name:
        doc["user"] = {"name": name}
    return doc


def bulk_index(cfg, events):
    """Index events with op_type create and _id = Graph event id (idempotent)."""
    ingested_at = utcnow()
    lines = []
    for ev in events:
        lines.append(json.dumps({"create": {"_index": cfg["data_stream"], "_id": ev["id"]}}))
        lines.append(json.dumps(transform(ev, ingested_at)))
    if not lines:
        return 0, 0
    resp = requests.post(
        cfg["elastic_url"].rstrip("/") + "/_bulk",
        data="\n".join(lines) + "\n",
        headers={
            "Authorization": f"ApiKey {cfg['elastic_api_key']}",
            "Content-Type": "application/x-ndjson",
        },
        timeout=60,
    )
    resp.raise_for_status()
    created = duplicates = 0
    for item in resp.json()["items"]:
        status = item["create"]["status"]
        if status in (200, 201):
            created += 1
        elif status == 409:
            duplicates += 1
        else:
            print("bulk error:", json.dumps(item["create"].get("error")), file=sys.stderr)
    return created, duplicates


def read_watermark(state_path, cfg):
    try:
        return parse_ts(json.loads(state_path.read_text())["watermark"])
    except (FileNotFoundError, KeyError, ValueError):
        return utcnow() - timedelta(hours=cfg["first_run_hours"])


def run_once(cfg, state_path):
    watermark = read_watermark(state_path, cfg)
    since = watermark - timedelta(minutes=cfg["lookback_minutes"])
    token = get_token(cfg)
    events = list(fetch_events(token, since))
    created, duplicates = bulk_index(cfg, events)
    if events:
        newest = max(parse_ts(e["activityDateTime"]) for e in events)
        watermark = max(watermark, newest)
    state_path.write_text(json.dumps({"watermark": iso(watermark)}))
    print(f"{iso(utcnow())} fetched={len(events)} created={created} already_present={duplicates} watermark={iso(watermark)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=str(HERE / "config.yaml"))
    ap.add_argument("--state", default=str(HERE / "state.json"))
    ap.add_argument("--loop", type=int, metavar="SECONDS", help="repeat every N seconds instead of running once")
    args = ap.parse_args()
    cfg = load_config(args.config)
    state_path = Path(args.state)
    if not args.loop:
        run_once(cfg, state_path)
        return
    while True:
        try:
            run_once(cfg, state_path)
        except requests.RequestException as exc:
            print(f"{iso(utcnow())} request failed: {exc}", file=sys.stderr)
        time.sleep(args.loop)


if __name__ == "__main__":
    main()