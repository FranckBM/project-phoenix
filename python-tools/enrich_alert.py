"""
Alert Enrichment Script — Project Phoenix (v2)

Takes detection alerts and enriches each one with:
  1. ATT&CK technique/tactic metadata (enrichment_data/attack_lookup.json)
  2. Host and user context (enrichment_data/asset_inventory.json, a static
     stand-in for a real CMDB/asset inventory)

Accepted input (detected automatically):
  - A simple alert JSON, as in enrichment_data/sample_alert.json
  - A Kibana Security alert document, nested or with flattened dotted keys
    (for example "kibana.alert.rule.name"), optionally wrapped in "_source"
  - An Elasticsearch search response ({"hits": {"hits": [...]}})
  - A JSON array of any of the above, or NDJSON (one alert per line)

Usage:
    python enrich_alert.py enrichment_data/sample_alert.json
    python enrich_alert.py alerts.ndjson --output enriched.json
    python enrich_alert.py enrichment_data/sample_kibana_alert.json --json
"""

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
ATTACK_LOOKUP_PATH = SCRIPT_DIR / "enrichment_data" / "attack_lookup.json"
ASSET_INVENTORY_PATH = SCRIPT_DIR / "enrichment_data" / "asset_inventory.json"

# Candidate source fields for each normalised field, in priority order.
# Simple-format keys come last so ECS/Kibana fields win when both exist.
FIELD_CANDIDATES = {
    "timestamp": ["kibana.alert.original_time", "@timestamp", "timestamp"],
    "rule_name": ["kibana.alert.rule.name", "rule.name", "rule_name"],
    "severity": ["kibana.alert.severity", "kibana.alert.rule.severity", "severity"],
    "host": ["host.name", "winlog.computer_name", "host"],
    "user": [
        "user.name",
        "winlog.event_data.User",
        "winlog.event_data.SubjectUserName",
        "aws.cloudtrail.user_identity.arn",
        "user",
    ],
    "process_image": ["process.executable", "winlog.event_data.Image", "process_image"],
    "command_line": ["process.command_line", "winlog.event_data.CommandLine", "command_line"],
}


class InputError(Exception):
    """Raised for unreadable or unusable input files."""


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def load_json(path: Path):
    """Load a JSON file, raising InputError if it's missing or malformed."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise InputError(f"required file not found: {path}")
    except json.JSONDecodeError as e:
        raise InputError(f"{path} is not valid JSON ({e})")


def load_alerts(path: Path) -> list:
    """Load one or many alerts from JSON, a JSON array, a search response or NDJSON."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise InputError(f"alert file not found: {path}")

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Fall back to NDJSON: one JSON document per non-empty line.
        data = []
        for n, line in enumerate(text.splitlines(), start=1):
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise InputError(f"{path} line {n} is not valid JSON ({e})")

    if isinstance(data, dict) and isinstance(data.get("hits"), dict):
        data = data["hits"].get("hits", [])
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data:
        raise InputError(f"{path} contains no alerts")

    alerts = []
    for item in data:
        if not isinstance(item, dict):
            raise InputError(f"{path} contains a non-object alert entry")
        alerts.append(item.get("_source", item))
    return alerts


# --------------------------------------------------------------------------
# Field access
# --------------------------------------------------------------------------

def get_field(doc, dotted: str):
    """
    Read a dotted field from a document that may be nested, flattened
    ("kibana.alert.rule.name" as one key) or a mix of both.
    """
    if not isinstance(doc, dict):
        return None
    if dotted in doc:
        return doc[dotted]
    parts = dotted.split(".")
    for i in range(1, len(parts)):
        head = ".".join(parts[:i])
        if head in doc:
            found = get_field(doc[head], ".".join(parts[i:]))
            if found is not None:
                return found
    return None


def first_string(doc: dict, candidates: list):
    """Return the first candidate field holding a non-empty string (or one-item list)."""
    for name in candidates:
        value = get_field(doc, name)
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        if isinstance(value, str) and value.strip():
            return value
    return None


def extract_technique_ids(doc: dict) -> list:
    """Collect ATT&CK technique IDs from simple fields or a Kibana rule's threat mapping."""
    ids = []
    simple = get_field(doc, "technique_ids") or get_field(doc, "technique_id")
    if isinstance(simple, str):
        ids.append(simple)
    elif isinstance(simple, list):
        ids.extend(t for t in simple if isinstance(t, str))

    threat = get_field(doc, "kibana.alert.rule.threat") or get_field(
        doc, "kibana.alert.rule.parameters.threat")
    for entry in threat if isinstance(threat, list) else []:
        for tech in entry.get("technique", []) or []:
            subs = [s.get("id") for s in tech.get("subtechnique", []) or [] if s.get("id")]
            # Prefer the precise sub-technique when the rule maps one.
            ids.extend(subs if subs else [tech.get("id")] if tech.get("id") else [])

    seen, unique = set(), []
    for t in ids:
        t = t.strip().upper()
        if t and t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def normalise_alert(doc: dict) -> dict:
    """Map any supported alert format onto one flat structure."""
    alert = {name: first_string(doc, cands) for name, cands in FIELD_CANDIDATES.items()}
    alert["technique_ids"] = extract_technique_ids(doc)
    return alert


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------

def enrich_attack_metadata(technique_ids: list, attack_lookup: dict) -> list:
    """Look up each technique; fall back to the parent technique if a sub-technique is missing."""
    if not technique_ids:
        return [{"status": "no ATT&CK technique on alert"}]
    results = []
    for tid in technique_ids:
        entry = attack_lookup.get(tid)
        matched = tid
        if entry is None and "." in tid:
            matched = tid.split(".")[0]
            entry = attack_lookup.get(matched)
        if entry is None:
            results.append({"technique_id": tid, "status": "not found in lookup table"})
        else:
            results.append({
                "technique_id": tid,
                "technique_name": entry["technique_name"],
                "tactics": entry["tactics"],
                **({"matched_parent": matched} if matched != tid else {}),
            })
    return results


def lookup_case_insensitive(table: dict, key: str):
    for k, v in table.items():
        if k.lower() == key.lower():
            return k, v
    return None, None


def enrich_host_context(host, asset_inventory: dict) -> dict:
    if not host:
        return {"status": "no host on alert"}
    name, entry = lookup_case_insensitive(asset_inventory.get("hosts", {}), host)
    if entry is None:
        return {"host": host, "status": "not found in asset inventory"}
    return {"host": name, **entry}


def enrich_user_context(user, asset_inventory: dict) -> dict:
    """Match the user as given, then without a DOMAIN\\ prefix or @domain suffix."""
    if not user:
        return {"status": "no user on alert"}
    users = asset_inventory.get("users", {})
    for candidate in (user, user.split("\\")[-1], user.split("@")[0]):
        name, entry = lookup_case_insensitive(users, candidate)
        if entry is not None:
            return {"user": name, **entry}
    return {"user": user, "status": "not found in asset inventory"}


def build_enriched_alert(doc: dict, attack_lookup: dict, asset_inventory: dict) -> dict:
    alert = normalise_alert(doc)
    return {
        "alert": alert,
        "enrichment": {
            "attack_metadata": enrich_attack_metadata(alert["technique_ids"], attack_lookup),
            "host_context": enrich_host_context(alert["host"], asset_inventory),
            "user_context": enrich_user_context(alert["user"], asset_inventory),
        },
    }


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def format_readable(enriched: dict) -> str:
    a = enriched["alert"]
    e = enriched["enrichment"]
    na = lambda v: v if v else "n/a"
    lines = ["=" * 64, f"ALERT: {na(a['rule_name'])}", "=" * 64,
             f"Timestamp   : {na(a['timestamp'])}",
             f"Severity    : {na(a['severity'])}", "", "--- ATT&CK Context ---"]
    for t in e["attack_metadata"]:
        if "technique_name" in t:
            lines.append(f"Technique   : {t['technique_id']} - {t['technique_name']}")
            lines.append(f"Tactic(s)   : {', '.join(t['tactics'])}")
        else:
            lines.append(f"({t.get('technique_id', '')} {t['status']})".replace("( ", "("))
    lines += ["", "--- Host Context ---"]
    h = e["host_context"]
    if "status" in h:
        lines.append(f"({h.get('host', '')} {h['status']})".replace("( ", "("))
    else:
        lines += [f"Host        : {h['host']}", f"Owner       : {h.get('owner', 'n/a')}",
                  f"Criticality : {h.get('criticality', 'n/a')}", f"Notes       : {h.get('notes', '')}"]
    lines += ["", "--- User Context ---"]
    u = e["user_context"]
    if "status" in u:
        lines.append(f"({u.get('user', '')} {u['status']})".replace("( ", "("))
    else:
        lines += [f"User        : {u['user']}", f"Role        : {u.get('role', 'n/a')}",
                  f"Privilege   : {u.get('privilege_level', 'n/a')}", f"Notes       : {u.get('notes', '')}"]
    lines += ["", "--- Raw Detection Detail ---",
              f"Process     : {na(a['process_image'])}",
              f"Command     : {na(a['command_line'])}", "=" * 64]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Enrich Project Phoenix detection alerts.")
    parser.add_argument("alert_file", type=Path, help="Alert file: JSON, JSON array, search response or NDJSON")
    parser.add_argument("--output", type=Path, help="Write the enriched alert(s) to this JSON file")
    parser.add_argument("--json", action="store_true", help="Print enriched JSON instead of the readable summary")
    args = parser.parse_args(argv)

    try:
        docs = load_alerts(args.alert_file)
        attack_lookup = load_json(ATTACK_LOOKUP_PATH)
        asset_inventory = load_json(ASSET_INVENTORY_PATH)
    except InputError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    enriched = [build_enriched_alert(d, attack_lookup, asset_inventory) for d in docs]
    result = enriched[0] if len(enriched) == 1 else enriched

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("\n\n".join(format_readable(x) for x in enriched))

    if args.output:
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\n{len(enriched)} enriched alert(s) written to: {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
