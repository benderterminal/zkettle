package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/taw/zkettle/cmd"
)

//go:embed web
var webFS embed.FS

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = cmd.RunServe(os.Args[2:], webFS)
	case "mcp":
		err = cmd.RunMCP(os.Args[2:], webFS, version)
	case "create":
		err = cmd.RunCreate(os.Args[2:])
	case "read":
		err = cmd.RunRead(os.Args[2:])
	case "revoke":
		err = cmd.RunRevoke(os.Args[2:])
	case "version":
		fmt.Println("zkettle", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	cmd.PrintBannerFull(os.Stderr)
	fmt.Fprintln(os.Stderr, `Usage: zkettle <command> [options]

Commands:
  serve     Start the HTTP server
  create    Encrypt and store a secret
  read      Retrieve and decrypt a secret
  revoke    Delete a secret
  mcp       Start MCP server (stdio) with HTTP backend
  version   Print version
  help      Show this help`)
}
