#!/bin/sh

# Release artifacts are built and scanned with this exact patched toolchain.
GO_VERSION=${GO_VERSION:-1.25.13}
if [ -z "${GO_TOOL_IMAGE:-}" ]; then
	if [ "$GO_VERSION" = 1.25.13 ]; then
		GO_TOOL_IMAGE="golang:1.25.13-bookworm@sha256:e401dae1bf814e29204a8cb7915682e1780951e609ca0dd8865ee1937f510c48"
	else
		GO_TOOL_IMAGE="golang:${GO_VERSION}-bookworm"
	fi
fi
TRIVY_IMAGE=${TRIVY_IMAGE:-aquasec/trivy:0.56.2@sha256:26245f364b6f5d223003dc344ec1eb5eb8439052bfecb31d79aeba0c74344b3a}
GOSEC_IMAGE=${GOSEC_IMAGE:-securego/gosec:2.22.8@sha256:5af1dca4d010f449eddfc3f6f39c9147bdb7e64fd7b953317ea793a78c95b90c}
export GO_VERSION GO_TOOL_IMAGE TRIVY_IMAGE GOSEC_IMAGE
