ARG GO_VERSION=1.25.0
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
COPY policies ./policies
COPY questions ./questions
COPY examples ./examples
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=1970-01-01T00:00:00Z
ENV SOURCE_DATE_EPOCH=0
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.buildVersion=${VERSION} -X main.buildCommit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /bin/security-gateway ./cmd/gateway

# scratch deliberately contains no shell, package manager, private key, or
# mutable filesystem. The gateway owns its explicitly mounted audit volume.
FROM scratch
WORKDIR /app
COPY --from=build /bin/security-gateway /bin/security-gateway
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY policies ./policies
COPY questions ./questions
COPY examples ./examples
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/bin/security-gateway", "--healthcheck"]
USER 65534:65534
ENTRYPOINT ["/bin/security-gateway"]
