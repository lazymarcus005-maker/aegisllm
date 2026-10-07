FROM golang:1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
RUN CGO_ENABLED=0 go build -o /bin/security-gateway ./cmd/gateway

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /bin/security-gateway /bin/security-gateway
COPY policies ./policies
COPY questions ./questions
COPY examples ./examples
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O - http://127.0.0.1:8080/health || exit 1
USER 65534:65534
ENTRYPOINT ["/bin/security-gateway"]
