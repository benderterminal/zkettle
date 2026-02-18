package cmd

import (
	"fmt"
	"io"
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
func PrintBannerFull(w io.Writer) {
	fmt.Fprint(w, bannerFull)
}
