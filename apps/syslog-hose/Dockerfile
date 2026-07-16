# Build context is apps/ (see deploy/compose.yaml): the image needs this app
# plus apps/shared (Go module + shared web components), so paths below are
# relative to apps/, not to this directory.

# --- UI build ---
FROM docker.io/library/node:22-alpine AS ui
WORKDIR /src/syslog-hose/web
COPY syslog-hose/web/package.json syslog-hose/web/package-lock.json ./
RUN npm ci
COPY shared/web/ /src/shared/web/
COPY syslog-hose/web/ ./
RUN npm run build

# --- Go build ---
FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /src/syslog-hose
COPY shared/go.mod /src/shared/go.mod
COPY syslog-hose/go.mod syslog-hose/go.sum ./
RUN go mod download
COPY shared/ /src/shared/
COPY syslog-hose/ ./
COPY --from=ui /src/syslog-hose/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /syslog-hose ./cmd/syslog-hose \
    && mkdir /data-skel

# --- Runtime ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /syslog-hose /syslog-hose
# pre-create /data owned by nonroot (65532) so named volumes inherit it
COPY --from=build --chown=65532:65532 /data-skel /data
ENV HOSE_ADDR=:8080 HOSE_DATA=/data
EXPOSE 8080
VOLUME /data
USER nonroot
ENTRYPOINT ["/syslog-hose"]
