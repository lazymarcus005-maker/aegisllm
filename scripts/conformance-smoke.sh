#!/bin/sh
set -eu

REPORT_DIR=${CONFORMANCE_REPORT_DIR:-"$(mktemp -d)"}
TARGET=${CONFORMANCE_TARGET:-http://127.0.0.1:18080}
echo "conformance report_dir=$REPORT_DIR target_configured=true"
go run ./cmd/conformancetool run --target "$TARGET" --report "$REPORT_DIR/report.json" --junit "$REPORT_DIR/report.xml"
go run ./cmd/conformancetool validate-report --report "$REPORT_DIR/report.json" --junit "$REPORT_DIR/report.xml"
go run ./cmd/conformancetool compare --baseline "$REPORT_DIR/report.json" --candidate "$REPORT_DIR/report.json" --report "$REPORT_DIR/compare.json"
echo "conformance smoke passed"
