# Engine image. The Go module vendors its only dependency, so the build needs
# no network beyond the base images.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY engine/go.mod engine/go.sum ./
COPY engine/vendor ./vendor
COPY engine/cmd ./cmd
COPY engine/internal ./internal
RUN CGO_ENABLED=0 go build -mod=vendor -o /out/mihakk ./cmd/mihakk

FROM alpine:3.21
# 10010 is the group that may use the control socket; the orchestrator's user is
# given it by the compose file. /run/mihakk is where the socket lives:
#   2770  owner and group only, nothing for anyone else -- the engine refuses to
#         start on a socket directory 'other' can enter -- and setgid, so the
#         socket is created in group 10010 without a chown the unprivileged
#         process could not make.
# A named volume mounted here starts as a copy of this directory, ownership and
# mode included, which is how the volume gets them.
RUN adduser -D -u 10003 mihakk \
 && addgroup -g 10010 mihakkctl \
 && addgroup mihakk mihakkctl \
 && mkdir -p /data /run/mihakk \
 && chown mihakk /data \
 && chown mihakk:mihakkctl /run/mihakk \
 && chmod 2770 /run/mihakk
COPY --from=build /out/mihakk /usr/local/bin/mihakk
USER mihakk

# The control API is on a Unix socket, on no network. The only TCP listener is
# the liveness endpoint, and the engine refuses to bind that anywhere but
# loopback -- inside the container's own network namespace, where no other
# container can reach it.
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8901/healthz || exit 1

ENTRYPOINT ["mihakk"]
CMD ["serve", "-socket", "/run/mihakk/control.sock", "-health-addr", "127.0.0.1:8901", "-data", "/data"]
