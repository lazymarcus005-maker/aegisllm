#!/usr/bin/env python3
"""Parse release static-security reports without confusing protocol events with findings."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys
from typing import Any

ALLOW_FIELDS = {"tool", "rule", "path", "line", "fingerprint", "owner", "reason", "expires_utc"}
TOOLS = {"gosec"}


def normalized_path(value: str) -> str:
    value = value.replace("\\", "/")
    for prefix in ("/src/", "./"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
    return value


def fingerprint(tool: str, rule: str, path: str, line: str, details: str) -> str:
    material = "|".join((tool, rule, normalized_path(path), str(line), details))
    return hashlib.sha256(material.encode()).hexdigest()


def load_allowlist(path: pathlib.Path) -> list[dict[str, Any]]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - release environment must provide it
        raise ValueError(f"PyYAML unavailable: {exc}") from exc
    try:
        document = yaml.safe_load(path.read_text())
    except Exception as exc:
        raise ValueError(f"allowlist YAML is malformed: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"schema_version", "entries"}:
        raise ValueError("allowlist must contain exactly schema_version and entries")
    if document["schema_version"] != "aegisllm.security-allowlist/v1":
        raise ValueError("unsupported allowlist schema")
    entries = document["entries"]
    if not isinstance(entries, list):
        raise ValueError("allowlist entries must be a list")
    now = dt.datetime.now(dt.timezone.utc)
    seen: set[str] = set()
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != ALLOW_FIELDS:
            raise ValueError("allowlist entry has an invalid schema")
        if entry["tool"] not in TOOLS or not all(isinstance(entry[k], str) for k in ALLOW_FIELDS - {"line"}):
            raise ValueError("allowlist entry has invalid scalar fields")
        if not isinstance(entry["line"], int) or entry["line"] <= 0:
            raise ValueError("allowlist line must be a positive integer")
        if not re.fullmatch(r"[0-9a-f]{64}", entry["fingerprint"]):
            raise ValueError("allowlist fingerprint must be lowercase SHA-256")
        if not entry["path"] or entry["path"].startswith("/") or ".." in pathlib.PurePosixPath(entry["path"]).parts:
            raise ValueError("allowlist path must be repository-relative")
        if not entry["owner"].strip() or not entry["reason"].strip():
            raise ValueError("allowlist owner and reason are required")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", entry["expires_utc"]):
            raise ValueError("allowlist expiry must be an explicit UTC timestamp")
        expiry = dt.datetime.fromisoformat(entry["expires_utc"].replace("Z", "+00:00"))
        if expiry <= now:
            raise ValueError(f"allowlist entry expired: {entry['fingerprint']}")
        if entry["fingerprint"] in seen:
            raise ValueError("duplicate allowlist fingerprint")
        seen.add(entry["fingerprint"])
        result.append(entry)
    return result


def parse_json_stream(path: pathlib.Path) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    raw = path.read_text()
    offset = 0
    events = []
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset >= len(raw):
            break
        event, offset = decoder.raw_decode(raw, offset)
        if not isinstance(event, dict):
            raise ValueError("scanner event is not an object")
        events.append(event)
    return events


def parse_gosec(path: pathlib.Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict) or not isinstance(document.get("Issues"), list):
        raise ValueError("gosec report has no Issues list")
    if document.get("Golang errors"):
        raise ValueError("gosec reported package-load errors")
    findings = []
    for item in document["Issues"]:
        if not isinstance(item, dict) or not all(key in item for key in ("rule_id", "file", "line", "details")):
            raise ValueError("gosec issue is malformed")
        item = dict(item)
        item["path"] = normalized_path(str(item["file"]))
        item["fingerprint"] = fingerprint("gosec", str(item["rule_id"]), item["path"], str(item["line"]), str(item["details"]))
        findings.append(item)
    return findings


def filter_gosec(findings: list[dict[str, Any]], allowlist: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    by_fingerprint = {entry["fingerprint"]: entry for entry in allowlist}
    suppressed = []
    unsuppressed = []
    matched: set[str] = set()
    for finding in findings:
        line = str(finding["line"])
        entry = by_fingerprint.get(finding["fingerprint"])
        if line.isdigit() and entry and entry["tool"] == "gosec" and entry["rule"] == finding["rule_id"] and entry["path"] == finding["path"] and entry["line"] == int(line):
            matched.add(entry["fingerprint"])
            suppressed.append({"tool": "gosec", "rule": finding["rule_id"], "path": finding["path"], "line": int(line), "details": finding["details"], "fingerprint": finding["fingerprint"], "owner": entry["owner"], "reason": entry["reason"], "expires_utc": entry["expires_utc"]})
        else:
            unsuppressed.append(finding)
    return suppressed, unsuppressed, sorted(set(by_fingerprint) - matched)


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        raise SystemExit("usage: static_report.py SECURITY_DIR STATICCHECK_EXIT GOVULNCHECK_EXIT GOSEC_EXIT")
    out = pathlib.Path(argv[1])
    exits = {"staticcheck": int(argv[2]), "govulncheck": int(argv[3]), "gosec": int(argv[4])}
    try:
        allowlist = load_allowlist(pathlib.Path("security/findings-allowlist.yaml"))
        static_lines = [
            line
            for line in (out / "staticcheck.txt").read_text(errors="replace").splitlines()
            if line.strip() and not line.startswith("-: error obtaining VCS status")
        ]
        govuln_events = parse_json_stream(out / "govulncheck.json")
        govuln_findings = [event["finding"] for event in govuln_events if "finding" in event]
        gosec_findings = parse_gosec(out / "gosec.json")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report = {"schema_version": "aegisllm.static/v1", "status": "blocked", "reason": f"scanner report unavailable or malformed: {exc}"}
        (out / "static-pinned.json").write_text(json.dumps(report, sort_keys=True) + "\n")
        return 1

    suppressed, unsuppressed, stale = filter_gosec(gosec_findings, allowlist)
    static_errors = exits["staticcheck"] != 0 and not static_lines
    govuln_errors = exits["govulncheck"] != 0 and not govuln_findings
    gosec_errors = exits["gosec"] != 0 and not gosec_findings
    status = "pass"
    reason = ""
    if stale:
        status, reason = "fail", "allowlist contains stale entries"
    elif static_errors or govuln_errors or gosec_errors:
        status, reason = "blocked", "scanner exited non-zero without a parseable finding; inspect tool logs"
    elif static_lines or govuln_findings or unsuppressed:
        status, reason = "fail", "actionable unsuppressed findings remain"
    report = {
        "schema_version": "aegisllm.static/v1",
        "status": status,
        "staticcheck": "2025.1.1",
        "staticcheck_unsuppressed": len(static_lines),
        "govulncheck": "v1.1.4",
        "govulncheck_reachable_unsuppressed": len(govuln_findings),
        "gosec": "v2.22.8",
        "gosec_unsuppressed": len(unsuppressed),
        "gosec_suppressed": len(suppressed),
        "suppressed_findings": suppressed,
        "allowlist": "security/findings-allowlist.yaml",
        "allowlist_stale": stale,
        "container": os.environ.get("GO_TOOL_IMAGE", "unknown"),
        "reason": reason,
    }
    (out / "static-pinned.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
