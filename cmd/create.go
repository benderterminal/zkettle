package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/taw/zkettle/internal/crypto"
)

const maxSecretSize = 500 * 1024 // 500KB — matches server-side encrypted limit

func RunCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	views := fs.Int("views", 1, "Max views before expiry")
	minutes := fs.Int("minutes", 1440, "Minutes until expiry (default 1440 = 24h)")
	serverURL := fs.String("server", "http://localhost:3000", "Server URL")
	jsonOut := fs.Bool("json", false, "Output JSON to stdout")
	quiet := fs.Bool("quiet", false, "Suppress stderr output")
	fs.BoolVar(quiet, "q", false, "Suppress stderr output (shorthand)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	// Reject positional arguments — secrets passed as CLI args are visible in
	// process lists (ps, /proc/*/cmdline) and shell history.
	if fs.NArg() > 0 && fs.Arg(0) != "-" {
		return fmt.Errorf("passing secrets as arguments exposes them in process lists and shell history\n\nUse stdin instead:\n  echo \"secret\" | zkettle create [options]\n  zkettle create [options]          # interactive prompt")
	}

	var plaintext string

	// Read from stdin (pipe, interactive prompt, or explicit "-")
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		// Interactive terminal — prompt
		if !*quiet && !*jsonOut {
			fmt.Fprint(os.Stderr, "Enter secret (then press Enter): ")
		}
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			plaintext = scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
	} else {
		// Piped input or explicit stdin ("-")
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxSecretSize+1))
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		if len(data) > maxSecretSize {
			return fmt.Errorf("secret exceeds %dKB limit", maxSecretSize/1024)
		}
		plaintext = string(data)
	}

	plaintext = strings.TrimRight(plaintext, "\n")
	if plaintext == "" {
		return fmt.Errorf("secret content is empty\n\nUsage:\n  echo \"secret\" | zkettle create [options]\n  zkettle create [options]          # interactive prompt")
	}

	ciphertext, iv, key, err := crypto.Encrypt([]byte(plaintext))
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	body := map[string]any{
		"encrypted": crypto.EncodeKey(ciphertext),
		"iv":        crypto.EncodeKey(iv),
		"views":     *views,
		"minutes":   *minutes,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	resp, err := httpClient.Post(*serverURL+"/api/secrets", "application/json", bytes.NewReader(b))
	if err != nil {
		return connError("posting to server", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID          string `json:"id"`
		ExpiresAt   string `json:"expires_at"`
		DeleteToken string `json:"delete_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	secretURL := fmt.Sprintf("%s/s/%s#%s", *serverURL, result.ID, crypto.EncodeKey(key))

	if *jsonOut {
		out := map[string]string{
			"url":          secretURL,
			"id":           result.ID,
			"delete_token": result.DeleteToken,
			"expires_at":   result.ExpiresAt,
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}

	fmt.Println(secretURL)
	if !*quiet {
		fmt.Fprintf(os.Stderr, "  expires: %s\n", result.ExpiresAt)
		fmt.Fprintf(os.Stderr, "  revoke:  zkettle revoke --server %s --token %s %s\n", *serverURL, result.DeleteToken, result.ID)
	}
	return nil
}
