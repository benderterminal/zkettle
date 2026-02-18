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
	"strings"
	"syscall"

	"github.com/taw/zkettle/internal/server"
	"github.com/taw/zkettle/internal/store"
)

func RunServe(args []string, webFS embed.FS) error {
	f := flag.NewFlagSet("serve", flag.ExitOnError)
	port := f.Int("port", 3000, "HTTP port")
	host := f.String("host", "0.0.0.0", "HTTP host")
	dataDir := f.String("data", "./data", "Data directory")
	baseURL := f.String("base-url", "", "Base URL for generated links")
	corsOrigins := f.String("cors-origins", "", "Comma-separated list of allowed CORS origins")
	if err := f.Parse(args); err != nil {
		return err
	}

	if *baseURL == "" {
		*baseURL = fmt.Sprintf("http://localhost:%d", *port)
	}

	var origins []string
	if *corsOrigins != "" {
		for _, o := range strings.Split(*corsOrigins, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
	}

	for _, o := range origins {
		if o == "*" {
			fmt.Fprintln(os.Stderr, "WARNING: CORS origin '*' allows any website to make cross-origin requests, disabling implicit CSRF protection")
			break
		}
	}

	return runServe(*host, *port, *dataDir, *baseURL, origins, webFS)
}

func runServe(host string, port int, dataDir, baseURL string, corsOrigins []string, webFS embed.FS) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	dbPath := dataDir + "/zkettle.db"
	st, err := store.New(dbPath)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}

	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		return fmt.Errorf("creating web fs: %w", err)
	}

	cfg := server.Config{BaseURL: baseURL}
	srv := server.New(cfg, st, subFS)

	handler := server.CORSMiddleware(corsOrigins)(server.RateLimiter(60, 60)(srv.Handler()))

	httpSrv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", host, port),
		Handler: handler,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		PrintBannerFull(os.Stderr)
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
