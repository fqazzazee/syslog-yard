.PHONY: build ui test run image

ui:
	cd web && npm ci && npm run build

build: ui
	go build -trimpath -ldflags="-s -w" -o syslog-valve ./cmd/syslog-valve

test:
	go test ./...

run: build
	VALVE_DATA=./data ./syslog-valve

image:
	podman build -t syslog-valve:latest . 2>/dev/null || docker build -t syslog-valve:latest .
