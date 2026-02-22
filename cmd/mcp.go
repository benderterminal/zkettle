package cmd

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/taw/zkettle/baseurl"
	"github.com/taw/zkettle/internal/config"
	"github.com/taw/zkettle/internal/mcptools"
	"github.com/taw/zkettle/server"
	"github.com/taw/zkettle/store"
	"github.com/taw/zkettle/internal/tunnel"
)

func RunMCP(args []string, webFS embed.FS, version string) error {
	f := flag.NewFlagSet("mcp", flag.ExitOnError)
	port := f.Int("port", 0, "HTTP port for API server")
	dataDir := f.String("data", "", "Data directory")
	baseURLFlag := f.String("base-url", "", "Base URL for generated links")
	host := f.String("host", "", "HTTP host")
	tunnelFlag := f.Bool("tunnel", false, "Expose server via Cloudflare Quick Tunnel")
	trustProxy := f.Bool("trust-proxy", false, "Trust X-Forwarded-For/X-Real-Ip headers (enable when behind a reverse proxy)")
	logFormat := f.String("log-format", "", "Log format: json or text")
	if err := f.Parse(args); err != nil {
		return err
	}

	flagSet := make(map[string]bool)
	f.Visit(func(fl *flag.Flag) { flagSet[fl.Name] = true })

	var flagCfg config.Config
	if flagSet["port"] {
		flagCfg.Port = *port
	}
	if flagSet["host"] {
		flagCfg.Host = *host
	}
	if flagSet["data"] {
		flagCfg.Data = *dataDir
	}
	if flagSet["base-url"] {
		flagCfg.BaseURL = *baseURLFlag
	}
	if flagSet["tunnel"] {
		flagCfg.Tunnel = *tunnelFlag
	}
	if flagSet["trust-proxy"] {
		flagCfg.TrustProxy = *trustProxy
	}
	if flagSet["log-format"] {
		flagCfg.LogFormat = *logFormat
	}

	defaults := config.Defaults()
	fileCfg, filePath, fileSet, err := config.LoadFile()
	if err != nil {
		return err
	}
	envCfg, envSet := config.LoadEnv()
	resolved := config.Merge(defaults, fileCfg, fileSet, envCfg, envSet, flagCfg, flagSet)

	if err := resolved.Validate(); err != nil {
		return err
	}

	if resolved.Tunnel && resolved.BaseURL != "" {
		return fmt.Errorf("--tunnel and --base-url are mutually exclusive")
	}

	bu := baseurl.New(fmt.Sprintf("http://localhost:%d", resolved.Port))
	if resolved.BaseURL != "" {
		bu.Set(resolved.BaseURL)
	}

	if err := os.MkdirAll(resolved.Data, 0o700); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	dbPath := resolved.Data + "/zkettle.db"
	st, err := store.New(dbPath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}

	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		st.Close()
		return fmt.Errorf("creating web fs: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	cfg := server.Config{BaseURL: bu, TrustProxy: resolved.TrustProxy}
	srv := server.New(ctx, cfg, st, subFS)
	handler := server.BuildHandler(ctx, cfg, srv.Handler())

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", resolved.Host, resolved.Port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start HTTP server in background
	go func() {
		PrintBannerFull(os.Stderr)
		slog.Info("HTTP server started", "host", resolved.Host, "port", resolved.Port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server failed", "error", err)
		}
	}()

	if resolved.Tunnel {
		tun, err := tunnel.Start(ctx, resolved.Port)
		if err != nil {
			tunShutdownCtx, tunCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer tunCancel()
			httpSrv.Shutdown(tunShutdownCtx)
			st.Close()
			return fmt.Errorf("starting tunnel: %w", err)
		}
		defer tun.Close()
		bu.Set(tun.URL())
		slog.Info("tunnel started", "url", tun.URL())
	}

	// Create and configure MCP server
	mcpSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "zkettle",
		Version: version,
	}, nil)

	mcptools.RegisterTools(mcpSrv, st, bu)

	// Run MCP server on stdio (blocks)
	err = mcpSrv.Run(ctx, &mcp.StdioTransport{})

	// Cleanup
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
	st.Close()

	return err
}
