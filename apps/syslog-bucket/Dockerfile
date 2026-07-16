# Build context is apps/ (see deploy/compose.yaml): the image needs this app
# plus apps/shared (Go module + shared web components), so paths below are
# relative to apps/, not to this directory.

# Stage 1: build the SPA
FROM docker.io/library/node:22-alpine AS webbuild
WORKDIR /src/syslog-bucket/web
COPY syslog-bucket/web/package.json syslog-bucket/web/package-lock.json* ./
RUN npm install
COPY shared/web/ /src/shared/web/
COPY syslog-bucket/web/ ./
RUN npm run build

# Stage 2: build the Go binary with the SPA embedded
FROM docker.io/library/golang:1.25-alpine AS gobuild
WORKDIR /src/syslog-bucket
COPY shared/go.mod /src/shared/go.mod
COPY syslog-bucket/go.mod syslog-bucket/go.sum ./
RUN go mod download
COPY shared/ /src/shared/
COPY syslog-bucket/ ./
COPY --from=webbuild /src/syslog-bucket/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /syslog-bucket ./cmd/syslog-bucket

# Stage 3: runtime
FROM docker.io/library/alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=gobuild /syslog-bucket /usr/local/bin/syslog-bucket
EXPOSE 8080 6601
ENTRYPOINT ["syslog-bucket"]
