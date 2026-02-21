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
	"github.com/taw/zkettle/internal/baseurl"
	"github.com/taw/zkettle/internal/mcptools"
	"github.com/taw/zkettle/internal/server"
	"github.com/taw/zkettle/internal/store"
	"github.com/taw/zkettle/internal/tunnel"
)

func RunMCP(args []string, webFS embed.FS, version string) error {
	f := flag.NewFlagSet("mcp", flag.ExitOnError)
	port := f.Int("port", 3000, "HTTP port for API server")
	dataDir := f.String("data", "./data", "Data directory")
	baseURLFlag := f.String("base-url", "", "Base URL for generated links")
	host := f.String("host", "127.0.0.1", "HTTP host (default 127.0.0.1 for local-only access)")
	tunnelFlag := f.Bool("tunnel", false, "Expose server via Cloudflare Quick Tunnel")
	trustProxy := f.Bool("trust-proxy", false, "Trust X-Forwarded-For/X-Real-Ip headers (enable when behind a reverse proxy)")
	if err := f.Parse(args); err != nil {
		return err
	}

	if *tunnelFlag && *baseURLFlag != "" {
		return fmt.Errorf("--tunnel and --base-url are mutually exclusive")
	}

	bu := baseurl.New(fmt.Sprintf("http://localhost:%d", *port))
	if *baseURLFlag != "" {
		bu.Set(*baseURLFlag)
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	dbPath := *dataDir + "/zkettle.db"
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

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg := server.Config{BaseURL: bu, TrustProxy: *trustProxy}
	srv := server.New(cfg, st, subFS)
	handler := server.BuildHandler(ctx, cfg, srv.Handler())

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", *host, *port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start HTTP server in background
	go func() {
		PrintBannerFull(os.Stderr)
		slog.Info("HTTP server started", "host", *host, "port", *port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server failed", "error", err)
		}
	}()

	if *tunnelFlag {
		tun, err := tunnel.Start(ctx, *port)
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
