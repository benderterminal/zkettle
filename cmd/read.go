package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/benderterminal/zkettle/id"
	"github.com/benderterminal/zkettle/internal/clipboard"
	"github.com/benderterminal/zkettle/internal/crypto"
	"github.com/benderterminal/zkettle/internal/outfile"
)

func RunRead(args []string) error {
	fs := flag.NewFlagSet("read", flag.ExitOnError)
	clipFlag := fs.Bool("clipboard", false, "Copy to clipboard instead of printing to stdout")
	fs.BoolVar(clipFlag, "c", false, "Copy to clipboard (shorthand)")
	fileFlag := fs.String("file", "", "Write to a new file (0600 permissions) instead of stdout; fails if it exists")
	fs.StringVar(fileFlag, "o", "", "Write to file (shorthand)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: zkettle read [options] <url>")
	}
	rawURL := fs.Arg(0)

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing URL: %w", err)
	}

	parts := strings.SplitN(u.Path, "/s/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return fmt.Errorf("invalid secret URL: expected /s/{id} in path")
	}
	secretID := parts[1]
	if !id.Valid(secretID) {
		return fmt.Errorf("invalid secret ID format")
	}

	keyStr := u.Fragment
	if keyStr == "" {
		return fmt.Errorf("no decryption key found in URL fragment")
	}
	key, err := crypto.DecodeKey(keyStr)
	if err != nil {
		return fmt.Errorf("decoding key: %w", err)
	}

	// Validate the output target before fetching: the fetch consumes a view.
	if *clipFlag && *fileFlag != "" {
		return fmt.Errorf("--clipboard and --file are mutually exclusive")
	}
	if *clipFlag && !clipboard.Available() {
		return clipboard.ErrUnavailable
	}
	var out *outfile.File
	if *fileFlag != "" {
		if out, err = outfile.Reserve(*fileFlag); err != nil {
			return err
		}
		defer out.Abort()
	}

	apiURL := fmt.Sprintf("%s://%s/api/secrets/%s", u.Scheme, u.Host, secretID)
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return connError("fetching secret", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("secret not found (expired or already viewed)")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var data struct {
		Encrypted string `json:"encrypted"`
		IV        string `json:"iv"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	ciphertext, err := crypto.DecodeKey(data.Encrypted)
	if err != nil {
		return fmt.Errorf("decoding ciphertext: %w", err)
	}
	iv, err := crypto.DecodeKey(data.IV)
	if err != nil {
		return fmt.Errorf("decoding iv: %w", err)
	}

	plaintext, err := crypto.Decrypt(ciphertext, iv, key)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}
	defer crypto.Zero(plaintext)
	defer crypto.Zero(key)

	if *clipFlag {
		if err := clipboard.Write(plaintext); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Secret copied to clipboard.")
		return nil
	}

	if out != nil {
		if err := out.Commit(plaintext); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Secret written to %s (0600 permissions)\n", *fileFlag)
		return nil
	}

	fmt.Println(string(plaintext))
	return nil
}
