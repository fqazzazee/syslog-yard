# --- UI build ---
FROM docker.io/library/node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- Go build ---
FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
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
