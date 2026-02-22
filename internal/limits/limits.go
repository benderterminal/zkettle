// Package limits defines shared validation constants for secret creation.
// Used by server handlers, MCP tools, and CLI commands.
package limits

const (
	DefaultViews   = 1
	MinViews       = 1
	MaxViews       = 100
	DefaultMinutes = 1440  // 24 hours
	MinMinutes     = 1
	MaxMinutes     = 43200 // 30 days

	// DefaultMaxSecretSize is the default encrypted secret size limit (500KB).
	// The server's maxBodySize (1MB) accommodates this after base64 + JSON overhead.
	DefaultMaxSecretSize = 500 * 1024
)
