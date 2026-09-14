"""
Alert Enrichment Script — Project Phoenix

Takes a raw detection alert (as produced by one of the lab's Sigma rules)
and enriches it with:
  1. ATT&CK technique/tactic metadata (from attack_lookup.json)
  2. Host and user context (from asset_inventory.json — a static stand-in
     for a real CMDB/asset inventory)

Outputs a readable, analyst-friendly enriched alert to the console and
optionally to a JSON file.

Usage:
    python enrich_alert.py sample_alert.json
    python enrich_alert.py sample_alert.json --output enriched_output.json
"""

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
ATTACK_LOOKUP_PATH = SCRIPT_DIR / "enrichment_data" / "attack_lookup.json"
ASSET_INVENTORY_PATH = SCRIPT_DIR / "enrichment_data" / "asset_inventory.json"


def load_json(path: Path) -> dict:
    """Load a JSON file, raising a clear error if it's missing or malformed."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: required file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: {path} is not valid JSON ({e})", file=sys.stderr)
        sys.exit(1)


def enrich_attack_metadata(alert: dict, attack_lookup: dict) -> dict:
    """Look up the alert's technique_id and attach the ATT&CK metadata."""
    technique_id = alert.get("technique_id")
    if not technique_id:
        return {"status": "no technique_id present on alert"}

    entry = attack_lookup.get(technique_id)
    if entry is None:
        return {"status": f"technique_id {technique_id} not found in lookup table"}

    return {
        "technique_id": technique_id,
        "technique_name": entry["technique_name"],
        "tactics": entry["tactics"],
    }


def enrich_host_context(alert: dict, asset_inventory: dict) -> dict:
    """Look up the alert's host in the asset inventory."""
    host = alert.get("host")
    if not host:
        return {"status": "no host present on alert"}

    entry = asset_inventory.get("hosts", {}).get(host)
    if entry is None:
        return {"status": f"host '{host}' not found in asset inventory", "host": host}

    return {"host": host, **entry}


def enrich_user_context(alert: dict, asset_inventory: dict) -> dict:
    """Look up the alert's user in the asset inventory."""
    user = alert.get("user")
    if not user:
        return {"status": "no user present on alert"}

    entry = asset_inventory.get("users", {}).get(user)
    if entry is None:
        return {"status": f"user '{user}' not found in asset inventory", "user": user}

    return {"user": user, **entry}


def build_enriched_alert(alert: dict, attack_lookup: dict, asset_inventory: dict) -> dict:
    """Combine the raw alert with all enrichment sections into one structure."""
    return {
        "original_alert": alert,
        "enrichment": {
            "attack_metadata": enrich_attack_metadata(alert, attack_lookup),
            "host_context": enrich_host_context(alert, asset_inventory),
            "user_context": enrich_user_context(alert, asset_inventory),
        },
    }


def print_readable(enriched: dict) -> None:
    """Print a human-readable summary of the enriched alert to the console."""
    alert = enriched["original_alert"]
    attack = enriched["enrichment"]["attack_metadata"]
    host = enriched["enrichment"]["host_context"]
    user = enriched["enrichment"]["user_context"]

    print("=" * 60)
    print(f"ALERT: {alert.get('rule_name', 'unknown rule')}")
    print("=" * 60)
    print(f"Timestamp : {alert.get('timestamp', 'n/a')}")
    print(f"Severity  : {alert.get('severity', 'n/a')}")
    print()

    print("--- ATT&CK Context ---")
    if "technique_name" in attack:
        print(f"Technique : {attack['technique_id']} — {attack['technique_name']}")
        print(f"Tactic(s) : {', '.join(attack['tactics'])}")
    else:
        print(f"({attack.get('status', 'no ATT&CK data available')})")
    print()

    print("--- Host Context ---")
    if "owner" in host:
        print(f"Host      : {host['host']}")
        print(f"Owner     : {host['owner']}")
        print(f"Criticality: {host['criticality']}")
        print(f"Notes     : {host.get('notes', '')}")
    else:
        print(f"({host.get('status', 'no host data available')})")
    print()

    print("--- User Context ---")
    if "role" in user:
        print(f"User      : {user['user']}")
        print(f"Role      : {user['role']}")
        print(f"Privilege : {user['privilege_level']}")
        print(f"Notes     : {user.get('notes', '')}")
    else:
        print(f"({user.get('status', 'no user data available')})")
    print()

    print("--- Raw Detection Detail ---")
    print(f"Process   : {alert.get('process_image', 'n/a')}")
    print(f"Command   : {alert.get('command_line', 'n/a')}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Enrich a Project Phoenix detection alert.")
    parser.add_argument("alert_file", type=Path, help="Path to the raw alert JSON file")
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Optional path to write the enriched alert as JSON"
    )
    args = parser.parse_args()

    alert = load_json(args.alert_file)
    attack_lookup = load_json(ATTACK_LOOKUP_PATH)
    asset_inventory = load_json(ASSET_INVENTORY_PATH)

    enriched = build_enriched_alert(alert, attack_lookup, asset_inventory)

    print_readable(enriched)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(enriched, f, indent=2)
        print(f"\nEnriched alert written to: {args.output}")


if __name__ == "__main__":
    main()