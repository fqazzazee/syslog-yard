module github.com/syslog-yard/syslog-hose

go 1.26.4

require (
	github.com/syslog-yard/shared v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

// The shared module lives in this repo and is never published; the Docker
// build copies apps/ wholesale so the relative path holds there too.
replace github.com/syslog-yard/shared => ../shared
