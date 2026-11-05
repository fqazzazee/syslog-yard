# Build context is apps/ (see deploy/compose.yaml): the image needs this app
# plus apps/shared (Go module + shared web components), so paths below are
# relative to apps/, not to this directory.

# Stage 1: build the SPA
FROM docker.io/library/node:22-alpine AS webbuild
WORKDIR /src/syslog-bucket/web
COPY syslog-bucket/web/package.json syslog-bucket/web/package-lock.json ./
RUN npm ci
COPY shared/web/ /src/shared/web/
COPY syslog-bucket/web/ ./
RUN npm run build

# Stage 2: build the Go binary with the SPA embedded
FROM docker.io/library/golang:1.26-alpine AS gobuild
WORKDIR /src/syslog-bucket
COPY shared/go.mod /src/shared/go.mod
COPY syslog-bucket/go.mod syslog-bucket/go.sum ./
RUN go mod download
COPY shared/ /src/shared/
COPY syslog-bucket/ ./
COPY --from=webbuild /src/syslog-bucket/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /syslog-bucket ./cmd/syslog-bucket

# Stage 3: runtime. The bucket keeps all state in Postgres and only binds
# unprivileged ports (8080 UI/API, 6601 ingest), so it runs as an
# unprivileged system user. busybox wget stays for the compose healthcheck.
FROM docker.io/library/alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 bucket \
    && adduser -S -D -H -u 10001 -G bucket -s /sbin/nologin bucket
COPY --from=gobuild /syslog-bucket /usr/local/bin/syslog-bucket
EXPOSE 8080 6601
USER 10001:10001
ENTRYPOINT ["syslog-bucket"]
