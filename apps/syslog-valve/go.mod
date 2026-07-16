module github.com/syslog-yard/syslog-valve

go 1.24

require github.com/syslog-yard/shared v0.0.0

// The shared module lives in this repo and is never published; the Docker
// build copies apps/ wholesale so the relative path holds there too.
replace github.com/syslog-yard/shared => ../shared
