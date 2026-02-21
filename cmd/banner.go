package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/mattn/go-isatty"
)

const bannerShort = `
        ) )
       ( (
     _  ~)~
 ___| |/ /
|_  / ' /
 / /| . \
/___|_|\_\
`

const bannerFull = `
        ) )
       ( (
     _  ~)~   _   _   _
 ___| |/ /___| |_| |_| | ___
|_  / ' // _ \ __| __| |/ _ \
 / /| . \  __/ |_| |_| |  __/
/___|_|\_\___|\__|\__|_|\___|
`

// PrintBanner writes the short zK logo to the given writer.
func PrintBanner(w io.Writer) {
	fmt.Fprint(w, bannerShort)
}

// PrintBannerFull writes the full zKettle logo to the given writer.
// Suppressed when the writer is not a terminal (e.g. piped or redirected).
func PrintBannerFull(w io.Writer) {
	if f, ok := w.(*os.File); ok && !isatty.IsTerminal(f.Fd()) && !isatty.IsCygwinTerminal(f.Fd()) {
		return
	}
	fmt.Fprint(w, bannerFull)
}
