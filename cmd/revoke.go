package cmd

import (
	"flag"
	"fmt"
	"io"
	"net/http"
)

func RunRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	serverURL := fs.String("server", "http://localhost:3000", "Server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: zkettle revoke [options] <id>")
	}
	id := fs.Arg(0)

	req, err := http.NewRequest("DELETE", *serverURL+"/api/secrets/"+id, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("deleting secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("secret revoked")
	return nil
}
