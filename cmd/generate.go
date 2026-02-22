package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/taw/zkettle/internal/generate"
)

func RunGenerate(args []string) error {
	f := flag.NewFlagSet("generate", flag.ExitOnError)
	length := f.Int("length", 32, "Length of generated secret")
	charset := f.String("charset", "alphanumeric", "Character set: alphanumeric, symbols, hex, base64url")
	if err := f.Parse(args); err != nil {
		return err
	}

	if *length < 1 || *length > 4096 {
		return fmt.Errorf("length must be 1-4096")
	}

	var chars string
	switch *charset {
	case "alphanumeric":
		chars = generate.Alphanumeric
	case "symbols":
		chars = generate.Symbols
	case "hex":
		chars = generate.Hex
	case "base64url":
		chars = generate.Base64URL
	default:
		return fmt.Errorf("unknown charset %q (use: alphanumeric, symbols, hex, base64url)", *charset)
	}

	secret, err := generate.RandomString(*length, chars)
	if err != nil {
		return err
	}

	// Write without trailing newline for clean piping
	fmt.Fprint(os.Stdout, secret)
	return nil
}
