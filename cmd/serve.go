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

	"github.com/taw/zkettle/internal/server"
	"github.com/taw/zkettle/internal/store"
)

func RunServe(args []string, webFS embed.FS) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 3000, "HTTP port")
	host := fs.String("host", "0.0.0.0", "HTTP host")
	dataDir := fs.String("data", "./data", "Data directory")
	baseURL := fs.String("base-url", "", "Base URL for generated links")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *baseURL == "" {
		*baseURL = fmt.Sprintf("http://localhost:%d", *port)
	}

	return runServe(*host, *port, *dataDir, *baseURL, webFS)
}

func runServe(host string, port int, dataDir, baseURL string, webFS embed.FS) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	dbPath := dataDir + "/zkettle.db"
	st, err := store.New(dbPath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}

	viewerFS, err := fs.Sub(webFS, "web")
	if err != nil {
		return fmt.Errorf("creating viewer fs: %w", err)
	}

	cfg := server.Config{BaseURL: baseURL}
	srv := server.New(cfg, st, viewerFS)

	handler := server.RateLimiter(60, 60)(srv.Handler())

	httpSrv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", host, port),
		Handler: handler,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "zkettle serving on %s:%d\n", host, port)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\nshutting down...")
		httpSrv.Shutdown(context.Background())
		st.Close()
		return nil
	case err := <-errCh:
		st.Close()
		return err
	}
}
