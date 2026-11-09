"""Tests for enrich_alert.py. Run from python-tools/:  python -m unittest discover tests"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import enrich_alert as ea  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "enrichment_data"
LOOKUP = json.loads((DATA / "attack_lookup.json").read_text(encoding="utf-8"))
INVENTORY = json.loads((DATA / "asset_inventory.json").read_text(encoding="utf-8"))


class FieldAccess(unittest.TestCase):
    def test_nested_flattened_and_mixed(self):
        self.assertEqual(ea.get_field({"a": {"b": {"c": 1}}}, "a.b.c"), 1)
        self.assertEqual(ea.get_field({"a.b.c": 2}, "a.b.c"), 2)
        self.assertEqual(ea.get_field({"a": {"b.c": 3}}, "a.b.c"), 3)
        self.assertIsNone(ea.get_field({"a": "text"}, "a.b"))

    def test_object_valued_field_is_not_a_string(self):
        # ECS "host" is an object; it must not be mistaken for a host name.
        self.assertIsNone(ea.first_string({"host": {"os": "win"}}, ["host"]))


class TechniqueExtraction(unittest.TestCase):
    def test_simple_format(self):
        self.assertEqual(ea.extract_technique_ids({"technique_id": "t1112"}), ["T1112"])

    def test_kibana_threat_prefers_subtechnique(self):
        doc = {"kibana.alert.rule.threat": [{"technique": [
            {"id": "T1021", "subtechnique": [{"id": "T1021.002"}]},
            {"id": "T1105"}]}]}
        self.assertEqual(ea.extract_technique_ids(doc), ["T1021.002", "T1105"])

    def test_duplicates_removed(self):
        doc = {"technique_ids": ["T1112", "t1112"]}
        self.assertEqual(ea.extract_technique_ids(doc), ["T1112"])


class Enrichment(unittest.TestCase):
    def test_parent_fallback(self):
        result = ea.enrich_attack_metadata(["T1059.999"], LOOKUP)[0]
        self.assertEqual(result["matched_parent"], "T1059")

    def test_unknown_technique_reported_not_raised(self):
        result = ea.enrich_attack_metadata(["T9999"], LOOKUP)[0]
        self.assertIn("not found", result["status"])

    def test_host_case_insensitive(self):
        self.assertEqual(ea.enrich_host_context("win11-rebuild", INVENTORY)["host"], "WIN11-REBUILD")

    def test_user_domain_prefix_stripped(self):
        self.assertEqual(ea.enrich_user_context("WIN11-REBUILD\\vboxuser", INVENTORY)["user"], "vboxuser")

    def test_missing_fields_give_status(self):
        enriched = ea.build_enriched_alert({}, LOOKUP, INVENTORY)
        self.assertIn("status", enriched["enrichment"]["host_context"])
        self.assertIn("status", enriched["enrichment"]["user_context"])


class Loading(unittest.TestCase):
    def _write(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        f.write(text)
        f.close()
        return Path(f.name)

    def test_samples_load_and_agree(self):
        simple = ea.normalise_alert(ea.load_alerts(DATA / "sample_alert.json")[0])
        kibana = ea.normalise_alert(ea.load_alerts(DATA / "sample_kibana_alert.json")[0])
        self.assertEqual(simple["technique_ids"], kibana["technique_ids"])
        self.assertEqual(simple["rule_name"], kibana["rule_name"])

    def test_search_response_and_source_unwrapped(self):
        path = self._write(json.dumps({"hits": {"hits": [
            {"_source": {"rule_name": "A"}}, {"_source": {"rule_name": "B"}}]}}))
        self.assertEqual([d["rule_name"] for d in ea.load_alerts(path)], ["A", "B"])

    def test_ndjson(self):
        path = self._write('{"rule_name": "A"}\n\n{"rule_name": "B"}\n')
        self.assertEqual(len(ea.load_alerts(path)), 2)

    def test_bad_input_exits_1(self):
        self.assertEqual(ea.main([str(self._write("not json at all"))]), 1)
        self.assertEqual(ea.main(["does-not-exist.json"]), 1)


if __name__ == "__main__":
    unittest.main()
