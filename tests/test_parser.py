"""Tests for scripts/log_parser.py (standard library only)."""
import json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import log_parser  # noqa: E402

SAMPLE = os.path.join(ROOT, "samples", "sample_alerts.json")


def load_samples():
    with open(SAMPLE, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


class NormalizeTests(unittest.TestCase):
    def test_extracts_all_fields_from_4688(self):
        record = log_parser.normalize(load_samples()[3])  # Word -> cmd
        self.assertEqual(record["user"], "jsmith")
        self.assertTrue(record["process"].endswith("cmd.exe"))
        self.assertTrue(record["parent_process"].endswith("WINWORD.EXE"))
        self.assertEqual(record["command_line"], "cmd.exe /c calc.exe")
        self.assertEqual(record["rule_id"], "100010")

    def test_ignores_other_event_ids(self):
        self.assertIsNone(log_parser.normalize(load_samples()[6]))  # 4624 logon

    def test_missing_command_line_is_none_not_a_crash(self):
        record = log_parser.normalize(load_samples()[7])
        self.assertIsNone(record["command_line"])

    def test_empty_event_is_ignored(self):
        self.assertIsNone(log_parser.normalize({}))


class CommandLineTests(unittest.TestCase):
    def run_parser(self, *extra):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "log_parser.py"),
             "--log", SAMPLE, "--from-start", "--once", *extra],
            capture_output=True, text=True, check=True)

    def test_once_parses_seven_4688_events(self):
        result = self.run_parser()
        self.assertEqual(result.stdout.count("[4688]"), 7)
        self.assertIn("Parsed 7 event(s)", result.stderr)

    def test_warns_when_command_line_missing(self):
        self.assertIn("No command line", self.run_parser().stderr)

    def test_out_file_is_valid_json_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            out = os.path.join(folder, "parsed.jsonl")
            self.run_parser("--out", out)
            with open(out, encoding="utf-8") as handle:
                rows = [json.loads(line) for line in handle]
        self.assertEqual(len(rows), 7)
        self.assertIn("parent_process", rows[0])

    def test_missing_log_file_returns_error(self):
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "log_parser.py"), "--log", "/nonexistent.json", "--once"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
