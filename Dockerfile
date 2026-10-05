FROM golang:1-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /bin/security-gateway ./cmd/gateway

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /bin/security-gateway /bin/security-gateway
USER nobody
ENTRYPOINT ["/bin/security-gateway"]
