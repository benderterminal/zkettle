package cmd

import (
	"net/http"
	"time"
)

// httpClient is a shared HTTP client with a reasonable timeout
// for all outbound CLI requests.
var httpClient = &http.Client{Timeout: 30 * time.Second}
