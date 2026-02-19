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
	"time"

	"github.com/taw/zkettle/internal/baseurl"
	"github.com/taw/zkettle/internal/server"
	"github.com/taw/zkettle/internal/store"
	"github.com/taw/zkettle/internal/tunnel"
)

func RunServe(args []string, webFS embed.FS) error {
	f := flag.NewFlagSet("serve", flag.ExitOnError)
	port := f.Int("port", 3000, "HTTP port")
	host := f.String("host", "0.0.0.0", "HTTP host")
	dataDir := f.String("data", "./data", "Data directory")
	baseURLFlag := f.String("base-url", "", "Base URL for generated links")
	corsOrigins := f.String("cors-origins", "", "Comma-separated list of allowed CORS origins")
	tunnelFlag := f.Bool("tunnel", false, "Expose server via Cloudflare Quick Tunnel")
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

	return runServe(*host, *port, *dataDir, bu, origins, *tunnelFlag, webFS)
}

func runServe(host string, port int, dataDir string, bu *baseurl.BaseURL, corsOrigins []string, useTunnel bool, webFS embed.FS) error {
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

	cfg := server.Config{BaseURL: bu}
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

	if useTunnel {
		tun, err := tunnel.Start(ctx, port)
		if err != nil {
			tunShutdownCtx, tunCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer tunCancel()
			httpSrv.Shutdown(tunShutdownCtx)
			st.Close()
			return fmt.Errorf("starting tunnel: %w", err)
		}
		defer tun.Close()
		bu.Set(tun.URL())
		waitForTunnel(tun.URL())
		fmt.Fprintf(os.Stderr, "\r\033[K\n  > open in browser: %s\n\n",
			hyperlink(tun.URL(), tun.URL()),
		)
	}

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\nshutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
		st.Close()
		return nil
	case err := <-errCh:
		st.Close()
		return err
	}
}

// waitForTunnel polls the tunnel URL with a countdown until it responds.
func waitForTunnel(tunnelURL string) {
	client := &http.Client{Timeout: 2 * time.Second}
	elapsed := 0
	for elapsed < 30 {
		fmt.Fprintf(os.Stderr, "\r\033[K  resolving tunnel (~30s)... %ds", elapsed)
		resp, err := client.Get(tunnelURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				fmt.Fprintf(os.Stderr, "\r\033[K  zkettle ready!")
				return
			}
		}
		time.Sleep(time.Second)
		elapsed++
	}
	fmt.Fprintf(os.Stderr, "\r\033[K  tunnel may still be resolving...")
}

// hyperlink returns an OSC 8 terminal hyperlink (clickable text).
// Supported by iTerm2, Terminal.app, VS Code, GNOME Terminal, Windows Terminal, etc.
func hyperlink(url, label string) string {
	return fmt.Sprintf("\033]8;;%s\033\\%s\033]8;;\033\\", url, label)
}
