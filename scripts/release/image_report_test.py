import json
import pathlib
import tempfile
import unittest

import image_report


class ImageReportTest(unittest.TestCase):
    def test_report_requires_db_metadata_and_counts_severity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "trivy.json").write_text(json.dumps({"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"ImageID": "sha256:image", "RepoDigests": ["image@sha256:digest"]}, "Results": [{"Target": "gateway", "Vulnerabilities": []}]}))
            (root / "db.json").write_text(json.dumps({"UpdatedAt": "2026-10-07T00:00:00Z", "NextUpdate": "2026-10-08T00:00:00Z", "DownloadedAt": "2026-10-07T01:00:00Z"}))
            output = root / "image-scan.json"
            self.assertEqual(image_report.main(["image_report.py", str(root / "trivy.json"), str(root / "db.json"), str(output), "test:tag", "0", "trivy:test"]), 0)
            self.assertEqual(json.loads(output.read_text())["vulnerability_count"], 0)


if __name__ == "__main__":
    unittest.main()
