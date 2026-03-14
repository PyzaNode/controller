package main

import (
	"embed"
	"io/fs"
)

// WebUI is the built web dashboard. Populated by building the web app
// with output dir controller/webui (base /dashboard/). Run: cd web && npm run build.
//
//go:embed webui
var webUI embed.FS

func webUIRoot() (fs.FS, error) {
	return fs.Sub(webUI, "webui")
}
