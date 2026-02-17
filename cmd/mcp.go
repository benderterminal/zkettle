package cmd

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/taw/zkettle/internal/mcptools"
	"github.com/taw/zkettle/internal/server"
	"github.com/taw/zkettle/internal/store"
)

func RunMCP(args []string, webFS embed.FS, version string) error {
	f := flag.NewFlagSet("mcp", flag.ExitOnError)
	port := f.Int("port", 3000, "HTTP port for API server")
	dataDir := f.String("data", "./data", "Data directory")
	baseURL := f.String("base-url", "", "Base URL for generated links")
	if err := f.Parse(args); err != nil {
		return err
	}

	if *baseURL == "" {
		*baseURL = fmt.Sprintf("http://localhost:%d", *port)
	}

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
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

	cfg := server.Config{BaseURL: *baseURL}
	srv := server.New(cfg, st, subFS)
	handler := server.RateLimiter(60, 60)(srv.Handler())

	httpSrv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", *port),
		Handler: handler,
	}

	// Start HTTP server in background
	go func() {
		PrintBanner(os.Stderr)
		fmt.Fprintf(os.Stderr, "zkettle HTTP server on port %d\n", *port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
		}
	}()

	// Create and configure MCP server
	mcpSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "zkettle",
		Version: version,
	}, nil)

	mcptools.RegisterTools(mcpSrv, st, *baseURL)

	// Run MCP server on stdio (blocks)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err = mcpSrv.Run(ctx, &mcp.StdioTransport{})

	// Cleanup
	httpSrv.Shutdown(context.Background())
	st.Close()

	return err
}
