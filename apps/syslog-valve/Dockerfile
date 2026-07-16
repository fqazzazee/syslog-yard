# Build context is apps/ (see deploy/compose.yaml): the image needs this app
# plus apps/shared (Go module + shared web components), so paths below are
# relative to apps/, not to this directory.

# --- UI build ---
FROM docker.io/library/node:22-alpine AS ui
WORKDIR /src/syslog-valve/web
COPY syslog-valve/web/package.json syslog-valve/web/package-lock.json ./
RUN npm ci
COPY shared/web/ /src/shared/web/
COPY syslog-valve/web/ ./
RUN npm run build

# --- Go build ---
FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /src/syslog-valve
COPY shared/go.mod /src/shared/go.mod
COPY syslog-valve/go.mod ./
RUN go mod download
COPY shared/ /src/shared/
COPY syslog-valve/ ./
COPY --from=ui /src/syslog-valve/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /syslog-valve ./cmd/syslog-valve

# --- Runtime: alpine because we ship syslog-ng as the data plane ---
FROM docker.io/library/alpine:3.22
RUN apk add --no-cache syslog-ng logrotate ca-certificates tzdata
COPY --from=build /syslog-valve /usr/local/bin/syslog-valve

# Runs as root so listeners on ports <1024 work inside the container
# (rootless podman/docker still confines this); revisit with
# cap_net_bind_service in the hardening pass.
ENV VALVE_ADDR=:8081 VALVE_DATA=/data
VOLUME /data
EXPOSE 8081
ENTRYPOINT ["syslog-valve"]
