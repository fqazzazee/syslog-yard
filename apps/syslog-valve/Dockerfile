# --- UI build ---
FROM node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- Go build ---
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /syslog-valve ./cmd/syslog-valve

# --- Runtime: alpine because we ship syslog-ng as the data plane ---
FROM alpine:3.22
RUN apk add --no-cache syslog-ng ca-certificates tzdata
COPY --from=build /syslog-valve /usr/local/bin/syslog-valve

# Runs as root so listeners on ports <1024 work inside the container
# (rootless podman/docker still confines this); revisit with
# cap_net_bind_service in the hardening pass.
ENV VALVE_ADDR=:8081 VALVE_DATA=/data
VOLUME /data
EXPOSE 8081
ENTRYPOINT ["syslog-valve"]
