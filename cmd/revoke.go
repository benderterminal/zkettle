package cmd

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func RunRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	serverURL := fs.String("server", "http://localhost:3000", "Server URL")
	token := fs.String("token", "", "Delete token (from create output)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: zkettle revoke --token <token> [options] <id>")
	}
	if *token == "" {
		*token = os.Getenv("ZKETTLE_DELETE_TOKEN")
	}
	if *token == "" {
		return fmt.Errorf("--token is required (or set ZKETTLE_DELETE_TOKEN env var)")
	}
	id := fs.Arg(0)

	req, err := http.NewRequest("DELETE", *serverURL+"/api/secrets/"+id, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return connError("deleting secret", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("secret revoked")
	return nil
}
