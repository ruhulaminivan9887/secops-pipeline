"""Keeps sigma_rules/*.yml and wazuh_rules/local_rules.xml in step. Needs: pip install pyyaml"""
import glob, os, re, unittest
import xml.etree.ElementTree as ET
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "wazuh_rules", "local_rules.xml")
SIGMA = os.path.join(ROOT, "sigma_rules")
def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


REQUIRED = ("title", "id", "status", "description", "author", "date", "tags", "logsource", "detection", "level")


class ParityTests(unittest.TestCase):
    def test_every_sigma_file_has_required_keys_and_condition(self):
        files = glob.glob(os.path.join(SIGMA, "*.yml"))
        self.assertEqual(len(files), 4)
        for path in files:
            doc = yaml.safe_load(read(path))
            for key in REQUIRED:
                self.assertIn(key, doc, f"{os.path.basename(path)} missing {key}")
            self.assertIn("condition", doc["detection"])

    def test_sigma_ids_are_unique(self):
        ids = [yaml.safe_load(read(p))["id"] for p in glob.glob(os.path.join(SIGMA, "*.yml"))]
        self.assertEqual(len(ids), len(set(ids)))

    def test_wazuh_comments_point_to_real_sigma_files(self):
        text = read(RULES)
        names = re.findall(r"<!-- Sigma: (\S+\.yml)", text)
        self.assertEqual(len(names), 5)
        for name in names:
            self.assertTrue(os.path.exists(os.path.join(SIGMA, name)), name)

    def test_attack_techniques_match_between_sigma_and_wazuh(self):
        wazuh = {}
        text = read(RULES)
        root = ET.fromstring("<root>" + text + "</root>")
        # pair each rule with the Sigma file named in the comment just before it
        for comment_file, rule in zip(re.findall(r"<!-- Sigma: (\S+\.yml)", text), root.iter("rule")):
            wazuh.setdefault(comment_file, set()).update(i.text.lower() for i in rule.findall("mitre/id"))
        for name, techniques in wazuh.items():
            doc = yaml.safe_load(read(os.path.join(SIGMA, name)))
            sigma = {t.replace("attack.", "") for t in doc["tags"] if re.match(r"attack\.t\d", t)}
            self.assertEqual(sigma, techniques, name)


if __name__ == "__main__":
    unittest.main()
