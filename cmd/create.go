package cmd

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/taw/zkettle/internal/crypto"
)

func RunCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	views := fs.Int("views", 1, "Max views before expiry")
	hours := fs.Int("hours", 24, "Hours until expiry")
	serverURL := fs.String("server", "http://localhost:3000", "Server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: zkettle create [options] <plaintext>")
	}
	plaintext := fs.Arg(0)

	// If plaintext is "-", read from stdin
	if plaintext == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
		plaintext = string(data)
	}

	ciphertext, iv, key, err := crypto.Encrypt([]byte(plaintext))
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	body := map[string]any{
		"encrypted": crypto.EncodeKey(ciphertext),
		"iv":        crypto.EncodeKey(iv),
		"views":     *views,
		"hours":     *hours,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	resp, err := http.Post(*serverURL+"/api/secrets", "application/json", bytes.NewReader(b))
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

	url := fmt.Sprintf("%s/s/%s#%s", *serverURL, result.ID, crypto.EncodeKey(key))
	fmt.Println(url)
	fmt.Fprintf(os.Stderr, "  expires: %s\n", result.ExpiresAt)
	fmt.Fprintf(os.Stderr, "  revoke:  zkettle revoke --server %s --token %s %s\n", *serverURL, result.DeleteToken, result.ID)
	return nil
}
