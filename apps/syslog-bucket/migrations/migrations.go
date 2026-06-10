// Package migrations embeds the SQL migration files so the binary can apply
// them at startup without shipping loose files.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
