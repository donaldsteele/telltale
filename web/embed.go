// Package web holds the server's page templates and static files, built
// into the binary.
package web

import "embed"

// FS holds templates/*.html and static/*.
//
//go:embed templates/*.html static/*
var FS embed.FS
