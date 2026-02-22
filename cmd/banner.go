package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/mattn/go-isatty"
)

const bannerFull = `
        ) )
       ( (
     _  ~)~   _   _   _
 ___| |/ /___| |_| |_| | ___
|_  / ' // _ \ __| __| |/ _ \
 / /| . \  __/ |_| |_| |  __/
/___|_|\_\___|\__|\__|_|\___|
`

// PrintBannerFull writes the full zKettle logo to the given writer.
// Suppressed when the writer is not a terminal (e.g. piped or redirected).
func PrintBannerFull(w io.Writer) {
	if f, ok := w.(*os.File); ok && !isatty.IsTerminal(f.Fd()) && !isatty.IsCygwinTerminal(f.Fd()) {
		return
	}
	fmt.Fprint(w, bannerFull)
}
