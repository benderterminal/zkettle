package cmd

import (
	"fmt"
	"strings"
)

// connError wraps an HTTP client error with a contextual hint.
// If the error is a DNS resolution failure, it suggests flushing the DNS cache.
func connError(action string, err error) error {
	msg := err.Error()
	if strings.Contains(msg, "no such host") {
		return fmt.Errorf("%s: %w\n\n  DNS could not resolve the server hostname.\n  If the URL works in your browser, try flushing the DNS cache:\n    sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder", action, err)
	}
	return fmt.Errorf("%s: %w", action, err)
}
