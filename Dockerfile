FROM golang:1.26.0-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/heimdall ./cmd/heimdall && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/heimdall-agent ./cmd/heimdall-agent
RUN CGO_ENABLED=0 go build -trimpath -o /out/heimdall-load ./cmd/heimdall-load

FROM builder AS tests
ENV CGO_ENABLED=1
ENTRYPOINT ["go", "test", "-race", "-v", "-tags=integration", "./internal/platform/postgres"]

FROM debian:bookworm-slim AS loadtest
COPY --from=builder /out/heimdall-load /usr/local/bin/heimdall-load
USER 10001:10001
ENTRYPOINT ["heimdall-load"]

FROM debian:bookworm-slim AS controlplane
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* && groupadd -g 10001 heimdall && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin heimdall
COPY --from=builder /out/heimdall /usr/local/bin/heimdall
USER 10001:10001
ENTRYPOINT ["heimdall"]
CMD ["-config", "/config/controlplane.yaml"]

FROM debian:bookworm-slim AS node
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo passwd ca-certificates util-linux curl procps && rm -rf /var/lib/apt/lists/* && groupadd -g 998 heimdall-agent && useradd -u 998 -g 998 -M -s /usr/sbin/nologin heimdall-agent && mkdir -p /run/sshd /etc/heimdall/authorized_keys /etc/heimdall/users /var/lib/heimdall-agent && chown 998:998 /var/lib/heimdall-agent
COPY --from=builder /out/heimdall-agent /usr/local/bin/
COPY deployments/node-entrypoint.sh /usr/local/bin/node-entrypoint
COPY deployments/sshd_config /usr/share/heimdall/sshd_config
ENTRYPOINT ["/usr/local/bin/node-entrypoint"]
