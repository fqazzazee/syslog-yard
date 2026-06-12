// Package web embeds the built UI (web/dist, produced by `npm run build`;
// the Docker multi-stage build runs it). web/dist/index.html is committed as a
// placeholder so `go build`/`go test` (and CI) satisfy the embed before the
// frontend is built; the hashed assets stay gitignored.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// Dist returns the built UI rooted at its index.html.
func Dist() (fs.FS, error) { return fs.Sub(distFS, "dist") }
