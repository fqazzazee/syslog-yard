# Stage 1: build the SPA
FROM docker.io/library/node:22-alpine AS webbuild
WORKDIR /src/web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

# Stage 2: build the Go binary with the SPA embedded
FROM docker.io/library/golang:1.25-alpine AS gobuild
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=webbuild /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /syslog-bucket ./cmd/syslog-bucket

# Stage 3: runtime
FROM docker.io/library/alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=gobuild /syslog-bucket /usr/local/bin/syslog-bucket
EXPOSE 8080 6601
ENTRYPOINT ["syslog-bucket"]
