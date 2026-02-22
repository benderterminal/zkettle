package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/benderterminal/zkettle/baseurl"
	"github.com/benderterminal/zkettle/internal/config"
)

// initRuntime resolves configuration from file/env/flags, creates a BaseURL,
// and initializes the global slog logger. Shared by RunServe and RunMCP.
func initRuntime(flagCfg config.Config, flagSet map[string]bool) (config.Config, *baseurl.BaseURL, error) {
	resolved, filePath, err := config.ResolveAll(flagCfg, flagSet)
	if err != nil {
		return config.Config{}, nil, err
	}

	bu := baseurl.New(fmt.Sprintf("http://localhost:%d", resolved.Port))
	if resolved.BaseURL != "" {
		bu.Set(resolved.BaseURL)
	}

	var logHandler slog.Handler
	if resolved.LogFormat == "json" {
		logHandler = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		logHandler = slog.NewTextHandler(os.Stderr, nil)
	}
	slog.SetDefault(slog.New(logHandler))

	if filePath != "" {
		slog.Info("loaded config file", "path", filePath)
	}

	return resolved, bu, nil
}
