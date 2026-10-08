#!/usr/bin/env python3
"""Validate Trivy's final-image report and its vulnerability database metadata."""

import datetime as dt
import json
import pathlib
import sys


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def main(argv: list[str]) -> int:
    if len(argv) != 7:
        raise SystemExit("usage: image_report.py TRIVY_JSON DB_METADATA IMAGE_REPORT TAG SCAN_EXIT SCANNER")
    trivy_path, db_path, report_path, tag = map(pathlib.Path, argv[1:5])
    scan_exit = int(argv[5])
    scanner = argv[6]
    try:
        report = json.loads(trivy_path.read_text())
        db = json.loads(db_path.read_text())
        if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
            raise ValueError("unexpected Trivy report schema or artifact type")
        metadata = report.get("Metadata", {})
        if not metadata.get("ImageID") or not metadata.get("RepoDigests"):
            raise ValueError("Trivy report lacks immutable image metadata")
        for key in ("UpdatedAt", "NextUpdate", "DownloadedAt"):
            if key not in db:
                raise ValueError(f"Trivy DB metadata lacks {key}")
            parse_time(db[key])
        if parse_time(db["DownloadedAt"]) < parse_time(db["UpdatedAt"]):
            raise ValueError("Trivy DB download predates its update")
        vulnerabilities = []
        severity_counts = {}
        for result in report.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                severity = vuln.get("Severity")
                if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                    raise ValueError(f"unknown Trivy severity: {severity}")
                vulnerabilities.append({"target": result.get("Target", ""), "id": vuln.get("VulnerabilityID", ""), "severity": severity, "status": vuln.get("Status", ""), "fixed_version": vuln.get("FixedVersion", "")})
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        output = {"schema_version": "aegisllm.image-scan/v1", "status": "blocked", "scanner": scanner, "database": "unavailable_or_unverified", "reason": str(exc)}
        report_path.write_text(json.dumps(output, sort_keys=True) + "\n")
        return 1
    if scan_exit != 0 and not vulnerabilities:
        status = "blocked"
        reason = "Trivy exited non-zero without reporting vulnerabilities; inspect trivy-tool.log"
    elif vulnerabilities:
        status = "fail"
        reason = "actionable vulnerabilities were found in the final image; inspect trivy.json"
    else:
        status, reason = "pass", ""
    output = {"schema_version": "aegisllm.image-scan/v1", "status": status, "scanner": scanner, "database": "available", "db_updated_at": db["UpdatedAt"], "db_next_update": db["NextUpdate"], "db_downloaded_at": db["DownloadedAt"], "artifact": str(tag), "image_id": metadata["ImageID"], "vulnerability_count": len(vulnerabilities), "severity_counts": severity_counts, "vulnerabilities": vulnerabilities, "reason": reason}
    report_path.write_text(json.dumps(output, sort_keys=True) + "\n")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
