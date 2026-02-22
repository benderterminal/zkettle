package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
)

func RunList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	serverURL := fs.String("server", "http://localhost:3000", "Server URL")
	adminToken := fs.String("admin-token", "", "Admin API bearer token")
	jsonOut := fs.Bool("json", false, "Output raw JSON")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	if *adminToken == "" {
		*adminToken = os.Getenv("ZKETTLE_ADMIN_TOKEN")
	}
	if *adminToken == "" {
		return fmt.Errorf("--admin-token is required (or set ZKETTLE_ADMIN_TOKEN env var)")
	}

	req, err := http.NewRequest("GET", *serverURL+"/api/admin/secrets", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+*adminToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return connError("listing secrets", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if *jsonOut {
		fmt.Println(string(body))
		return nil
	}

	var secrets []struct {
		ID        string `json:"id"`
		ViewsLeft int    `json:"views_left"`
		ExpiresAt string `json:"expires_at"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(body, &secrets); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if len(secrets) == 0 {
		fmt.Println("No active secrets.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tVIEWS LEFT\tEXPIRES AT\tCREATED AT")
	for _, s := range secrets {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", s.ID, s.ViewsLeft, s.ExpiresAt, s.CreatedAt)
	}
	tw.Flush()
	return nil
}
