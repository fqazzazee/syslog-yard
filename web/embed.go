// Package web embeds the built UI (web/dist, produced by `npm run build`).
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// Dist returns the built UI rooted at its index.html.
func Dist() (fs.FS, error) { return fs.Sub(distFS, "dist") }
