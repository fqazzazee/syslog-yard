.PHONY: build ui test run image

ui:
	cd web && npm ci && npm run build

build: ui
	go build -trimpath -ldflags="-s -w" -o syslog-valve ./cmd/syslog-valve

test:
	go test ./...

run: build
	VALVE_DATA=./data ./syslog-valve

# The build context is the parent apps/ dir: the image also copies apps/shared.
image:
	podman build -t syslog-valve:latest -f Dockerfile .. 2>/dev/null || docker build -t syslog-valve:latest -f Dockerfile ..
