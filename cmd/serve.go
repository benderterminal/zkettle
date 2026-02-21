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
	"strings"
	"syscall"
	"time"

	"github.com/taw/zkettle/internal/baseurl"
	"github.com/taw/zkettle/internal/config"
	"github.com/taw/zkettle/internal/server"
	"github.com/taw/zkettle/internal/store"
	"github.com/taw/zkettle/internal/tunnel"
)

func RunServe(args []string, webFS embed.FS) error {
	f := flag.NewFlagSet("serve", flag.ExitOnError)
	port := f.Int("port", 0, "HTTP port")
	host := f.String("host", "", "HTTP host (use 0.0.0.0 to listen on all interfaces)")
	dataDir := f.String("data", "", "Data directory")
	baseURLFlag := f.String("base-url", "", "Base URL for generated links")
	corsOrigins := f.String("cors-origins", "", "Comma-separated list of allowed CORS origins")
	tunnelFlag := f.Bool("tunnel", false, "Expose server via Cloudflare Quick Tunnel")
	trustProxy := f.Bool("trust-proxy", false, "Trust X-Forwarded-For/X-Real-Ip headers (enable when behind a reverse proxy)")
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
	if flagSet["cors-origins"] {
		var origins []string
		for _, o := range strings.Split(*corsOrigins, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
		flagCfg.CORSOrigins = origins
	}
	if flagSet["tunnel"] {
		flagCfg.Tunnel = *tunnelFlag
	}
	if flagSet["trust-proxy"] {
		flagCfg.TrustProxy = *trustProxy
	}

	defaults := config.Defaults()
	fileCfg, filePath, err := config.LoadFile()
	if err != nil {
		return err
	}
	envCfg, envSet := config.LoadEnv()
	resolved := config.Merge(defaults, fileCfg, filePath != "", envCfg, envSet, flagCfg, flagSet)

	if resolved.Tunnel && resolved.BaseURL != "" {
		return fmt.Errorf("--tunnel and --base-url are mutually exclusive")
	}

	bu := baseurl.New(fmt.Sprintf("http://localhost:%d", resolved.Port))
	if resolved.BaseURL != "" {
		bu.Set(resolved.BaseURL)
	}

	for _, o := range resolved.CORSOrigins {
		if o == "*" {
			fmt.Fprintln(os.Stderr, "WARNING: CORS origin '*' allows any website to make cross-origin requests, disabling implicit CSRF protection")
			break
		}
	}

	if filePath != "" {
		slog.Info("loaded config file", "path", filePath)
	}

	return runServe(resolved.Host, resolved.Port, resolved.Data, bu, resolved.CORSOrigins, resolved.Tunnel, resolved.TrustProxy, webFS)
}

func runServe(host string, port int, dataDir string, bu *baseurl.BaseURL, corsOrigins []string, useTunnel bool, trustProxy bool, webFS embed.FS) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	slog.Info("configuration",
		"port", port,
		"host", host,
		"data", dataDir,
		"base_url", bu.Get(),
		"cors_origins", corsOrigins,
		"trust_proxy", trustProxy,
	)

	cfg := server.Config{
		BaseURL:     bu,
		TrustProxy:  trustProxy,
		CORSOrigins: corsOrigins,
	}
	srv := server.New(cfg, st, subFS)

	handler := server.BuildHandler(ctx, cfg, srv.Handler())

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", host, port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		PrintBannerFull(os.Stderr)
		slog.Info("server started", "host", host, "port", port)
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
		fmt.Fprintf(os.Stderr, "\r\033[K\n")
		printQuickStart(tun.URL())
	} else {
		printQuickStart(fmt.Sprintf("http://%s:%d", host, port))
	}

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
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

// printQuickStart writes the server URL and example commands to stderr.
func printQuickStart(baseURL string) {
	fmt.Fprintf(os.Stderr, "  > open homepage:\n")
	fmt.Fprintf(os.Stderr, "    %s\n\n", hyperlink(baseURL, baseURL))
	fmt.Fprintf(os.Stderr, "  > create a secret:\n")
	fmt.Fprintf(os.Stderr, "    echo \"my secret\" | zkettle create --server %s --views 2 --minutes 60\n\n", baseURL)
	fmt.Fprintf(os.Stderr, "  > reveal a secret:\n")
	fmt.Fprintf(os.Stderr, "    zkettle read <secret-url>\n\n")
	fmt.Fprintf(os.Stderr, "  > revoke a secret:\n")
	fmt.Fprintf(os.Stderr, "    zkettle revoke --server %s --token <delete-token> <id>\n\n", baseURL)
	fmt.Fprintf(os.Stderr, "  > help:\n")
	fmt.Fprintf(os.Stderr, "    zkettle help\n\n")
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
