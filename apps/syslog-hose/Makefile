.PHONY: build ui test run image

ui:
	cd web && npm ci && npm run build

build: ui
	go build -trimpath -ldflags="-s -w" -o syshose ./cmd/syshose

test:
	go test ./...

run: build
	SYSHOSE_DATA=./data ./syshose

image:
	podman build -t syshose:latest . 2>/dev/null || docker build -t syshose:latest .
