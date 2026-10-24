import json
import unittest

from analysis_engine import analyze_logs, normalize_template, ngram_anomaly_scores, parse_uploaded_text


class LogAnalysisTests(unittest.TestCase):
    def test_detects_common_categories_across_components(self):
        lines = [
            "kernel: Out of memory: Killed process 1842 (worker)",
            "nginx ERROR upstream timed out while reading response header",
            "sshd WARNING Failed password for admin from 203.0.113.4",
            "app ERROR TLS certificate verify failed",
            "postgres ERROR deadlock detected",
        ]
        findings = analyze_logs(lines)
        categories = {item["category"] for item in findings}
        self.assertIn("Resource exhaustion", categories)
        self.assertIn("Timeout or latency", categories)
        self.assertIn("Authentication or authorization", categories)
        self.assertIn("TLS or certificate", categories)
        self.assertIn("Database or storage", categories)
        self.assertTrue(all(item["is_anomaly"] for item in findings))

    def test_syslog_numeric_severity_and_http_status(self):
        findings = analyze_logs(["2026-10-24T10:00:00Z host app level=3 disk operation failed"])
        self.assertEqual(findings[0]["severity"], "ERROR")
        self.assertGreaterEqual(findings[0]["score"], 78)

    def test_rfc5424_syslog_priority_decodes_severity(self):
        finding = analyze_logs(["<11>1 2026-10-24T10:00:00Z host app 1 - - operation failed"])[0]
        self.assertEqual(finding["severity"], "ERROR")

    def test_rarity_does_not_flag_all_normal_unfamiliar_lines(self):
        lines = [f"worker message variant {number}" for number in range(1, 8)]
        findings = analyze_logs(lines, threshold=60)
        self.assertFalse(any(item["is_anomaly"] for item in findings))

    def test_ngram_model_scores_unusual_sequence(self):
        lines = [
            "api request accepted by worker",
            "api request accepted by worker",
            "api request accepted by worker",
            "api request accepted by worker",
            "kernel quantum-storage failure on shard",
        ]
        scores = ngram_anomaly_scores(lines)
        self.assertEqual(len(scores), len(lines))
        self.assertGreater(scores[-1], scores[0])
        self.assertIn("ngram_score", analyze_logs(lines)[-1])

    def test_template_normalizes_volatile_identifiers(self):
        first = normalize_template("2026-10-24T10:00:00Z request from 192.0.2.1 id=12345")
        second = normalize_template("2026-10-25T11:00:00Z request from 192.0.2.9 id=99999")
        self.assertEqual(first, second)

    def test_json_file_is_split_into_event_lines(self):
        data = json.dumps([{"level": "info", "message": "ready"}, {"level": "error", "message": "failed"}]).encode()
        parsed = parse_uploaded_text("events.json", data)
        self.assertEqual(len(parsed.splitlines()), 2)
        self.assertIn('"message":"failed"', parsed)

    def test_jsonl_is_preserved(self):
        raw = b'{"level":"info"}\n{"level":"error"}\n'
        self.assertEqual(parse_uploaded_text("events.jsonl", raw), raw.decode())

    def test_unknown_single_line_is_not_called_an_anomaly(self):
        result = analyze_logs(["custom daemon emitted unusual event"], threshold=60)[0]
        self.assertEqual(result["severity"], "UNKNOWN")
        self.assertFalse(result["is_anomaly"])
        self.assertEqual(result["category"], "Unusual or informational event")


if __name__ == "__main__":
    unittest.main()
