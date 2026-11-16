"""Checks that the Wazuh rules in wazuh_rules/local_rules.xml fire on the right events.

This is a small simulator: it applies each rule's <field> patterns to the sample events
with Python's `re`. Real matching is done by Wazuh (PCRE2), so also confirm new rules
with `sudo /var/ossec/bin/wazuh-logtest`. Standard library only.
"""
import json, os, re, unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "wazuh_rules", "local_rules.xml")
SAMPLE = os.path.join(ROOT, "samples", "sample_alerts.json")


def load_rules():
    with open(RULES, encoding="utf-8") as handle:
        tree = ET.fromstring("<root>" + handle.read() + "</root>")
    rules = []
    for rule in tree.iter("rule"):
        rules.append({
            "id": rule.get("id"),
            "level": int(rule.get("level")),
            "fields": [(f.get("name"), f.text) for f in rule.findall("field")],
            "frequency": rule.get("frequency"),
            "timeframe": rule.get("timeframe"),
            "if_matched_sid": (rule.findtext("if_matched_sid") or None),
            "mitre": [i.text for i in rule.findall("mitre/id")],
        })
    return rules


def lookup(event, dotted):
    node = event.get("data", {})
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return str(node)


def fired(event, rules):
    ids = []
    for rule in rules:
        if rule["frequency"]:
            continue  # frequency rules count repeated events over time; Wazuh does that, not this simulator
        ok = True
        for name, pattern in rule["fields"]:
            value = lookup(event, name)
            if value is None or not re.search(pattern, value):
                ok = False
                break
        if ok:
            ids.append(rule["id"])
    return ids


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules()
        with open(SAMPLE, encoding="utf-8") as handle:
            cls.events = [json.loads(line) for line in handle]

    def test_rule_ids_are_unique_and_in_custom_range(self):
        ids = [r["id"] for r in self.rules]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(100000 <= int(i) <= 119999 for i in ids))

    def test_brute_force_rule_is_a_frequency_rule_on_failed_logons(self):
        rule = next(r for r in self.rules if r["id"] == "100014")
        self.assertEqual(rule["if_matched_sid"], "60122")
        self.assertEqual(int(rule["frequency"]), 5)
        self.assertEqual(int(rule["timeframe"]), 60)
        self.assertEqual(rule["mitre"], ["T1110"])

    def test_whoami_fires_100012(self):
        self.assertEqual(fired(self.events[0], self.rules), ["100012"])

    def test_net_user_fires_100013(self):
        self.assertEqual(fired(self.events[1], self.rules), ["100013"])

    def test_encoded_powershell_fires_100011(self):
        self.assertEqual(fired(self.events[2], self.rules), ["100011"])

    def test_word_spawning_cmd_fires_100010(self):
        self.assertEqual(fired(self.events[3], self.rules), ["100010"])

    def test_normal_system_activity_fires_nothing(self):
        self.assertEqual(fired(self.events[4], self.rules), [])

    def test_powershell_bypass_from_management_agent_does_not_fire_encoded_rule(self):
        # False-positive check: -ExecutionPolicy Bypass is not an encoded command.
        self.assertEqual(fired(self.events[5], self.rules), [])

    def test_non_4688_events_fire_nothing(self):
        self.assertEqual(fired(self.events[6], self.rules), [])

    def test_encoded_rule_ignores_plain_command_and_short_blob(self):
        base = json.loads(json.dumps(self.events[2]))
        for cmd in ("powershell Get-Process", "powershell -e abc", "powershell -ExecutionPolicy Bypass -Command -"):
            base["data"]["win"]["eventdata"]["commandLine"] = cmd
            self.assertNotIn("100011", fired(base, self.rules), cmd)

    def test_net_rule_needs_enumeration_argument(self):
        base = json.loads(json.dumps(self.events[1]))
        base["data"]["win"]["eventdata"]["commandLine"] = "net use Z: \\\\server\\share"
        self.assertEqual(fired(base, self.rules), [])


if __name__ == "__main__":
    unittest.main()
