package leaderboard

import "embed"

// Files contains the self-contained leaderboard assets served by the gateway.
// No external CDN or runtime dependency is required.
//
//go:embed index.html style.css app.js
var Files embed.FS
