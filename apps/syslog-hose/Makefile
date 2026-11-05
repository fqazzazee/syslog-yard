.PHONY: build ui test run image

ui:
	cd web && npm ci && npm run build

build: ui
	go build -trimpath -ldflags="-s -w" -o syslog-hose ./cmd/syslog-hose

test:
	go test ./...

run: build
	HOSE_DATA=./data ./syslog-hose

# The build context is the parent apps/ dir: the image also copies apps/shared.
image:
	podman build -t syslog-hose:latest -f Dockerfile .. 2>/dev/null || docker build -t syslog-hose:latest -f Dockerfile ..
