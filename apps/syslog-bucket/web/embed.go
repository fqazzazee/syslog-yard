// Package web embeds the built SPA so the backend ships as a single binary.
// web/dist is produced by `vite build` (done in the Docker multi-stage
// build); the committed placeholder index.html keeps `go build` working
// before the frontend has been built.
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
