package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var tunnelURLRe = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

const startTimeout = 30 * time.Second

// Tunnel manages a cloudflared quick-tunnel process.
type Tunnel struct {
	cmd *exec.Cmd
	url string
}

// URL returns the public tunnel URL.
func (t *Tunnel) URL() string {
	return t.url
}

// Start spawns cloudflared and blocks until the tunnel URL is detected or the
// timeout expires. The context controls the lifetime of the cloudflared process.
func Start(ctx context.Context, localPort int) (*Tunnel, error) {
	path, err := exec.LookPath("cloudflared")
	if err != nil {
		return nil, fmt.Errorf("cloudflared not found on PATH\n\nInstall it:\n%s", installHint())
	}

	cmd := exec.CommandContext(ctx, path,
		"tunnel", "--url", fmt.Sprintf("http://localhost:%d", localPort), "--no-autoupdate",
	)

	// cloudflared prints the tunnel URL to stderr.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stderr pipe: %w", err)
	}

	cmd.Stdout = os.Stdout // let any stdout pass through

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting cloudflared: %w", err)
	}

	urlCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if u := tunnelURLRe.FindString(line); u != "" {
				select {
				case urlCh <- u:
				default:
				}
			}
		}
	}()

	select {
	case u := <-urlCh:
		return &Tunnel{cmd: cmd, url: u}, nil
	case <-time.After(startTimeout):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("timed out waiting for cloudflared tunnel URL (waited %s)", startTimeout)
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		return nil, ctx.Err()
	}
}

// Close shuts down the cloudflared process.
func (t *Tunnel) Close() error {
	if t.cmd == nil || t.cmd.Process == nil {
		return nil
	}
	_ = t.cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- t.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = t.cmd.Process.Kill()
	}
	return nil
}

func installHint() string {
	switch {
	case runtime.GOOS == "darwin":
		return "  brew install cloudflared"
	case runtime.GOOS == "linux" && isDebian():
		return "  sudo apt install cloudflared\n  or: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
	default:
		return "  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
	}
}

func isDebian() bool {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "debian") || strings.Contains(lower, "ubuntu")
}
