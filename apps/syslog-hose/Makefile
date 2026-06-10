.PHONY: build ui test run image

ui:
	cd web && npm ci && npm run build

build: ui
	go build -trimpath -ldflags="-s -w" -o syslog-hose ./cmd/syslog-hose

test:
	go test ./...

run: build
	HOSE_DATA=./data ./syslog-hose

image:
	podman build -t syslog-hose:latest . 2>/dev/null || docker build -t syslog-hose:latest .
