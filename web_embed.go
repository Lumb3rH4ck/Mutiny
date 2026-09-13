package main

import "embed"

// webAssets holds the static web UI served at "/" in both TUI and server
// modes. Embedding it (instead of http.Dir("web") resolved against the
// process CWD) means the UI is reachable no matter where mutiny is launched
// from.
//
//go:embed web
var webAssets embed.FS