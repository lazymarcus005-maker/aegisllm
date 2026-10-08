import pathlib
import tempfile
import unittest

import static_report


class StaticReportTest(unittest.TestCase):
    def test_fingerprint_is_stable_and_paths_are_repository_relative(self):
        value = static_report.fingerprint("gosec", "G115", "/src/internal/audit/durable.go", "353", "bounded")
        self.assertEqual(value, static_report.fingerprint("gosec", "G115", "internal/audit/durable.go", "353", "bounded"))

    def test_expired_and_stale_allowlist_entries_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "allowlist.yaml"
            path.write_text(
                "schema_version: aegisllm.security-allowlist/v1\nentries:\n"
                "  - tool: gosec\n    rule: G101\n    path: internal/example.go\n    line: 1\n"
                "    fingerprint: " + "0" * 64 + "\n    owner: security\n    reason: fixture\n"
                "    expires_utc: 2000-01-01T00:00:00Z\n"
            )
            with self.assertRaises(ValueError):
                static_report.load_allowlist(path)

    def test_empty_allowlist_is_strictly_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "allowlist.yaml"
            path.write_text("schema_version: aegisllm.security-allowlist/v1\nentries: []\n")
            self.assertEqual(static_report.load_allowlist(path), [])

    def test_unused_valid_entry_is_stale(self):
        entry = {
            "tool": "gosec", "rule": "G101", "path": "internal/example.go", "line": 1,
            "fingerprint": "0" * 64, "owner": "security", "reason": "fixture",
            "expires_utc": "2099-01-01T00:00:00Z",
        }
        _, _, stale = static_report.filter_gosec([], [entry])
        self.assertEqual(stale, ["0" * 64])


if __name__ == "__main__":
    unittest.main()
