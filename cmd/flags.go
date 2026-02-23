package cmd

import "strings"

// boolFlags is the set of flags that don't take a value argument.
var boolFlags = map[string]bool{
	"--json":        true,
	"-q":            true,
	"--quiet":       true,
	"--tunnel":      true,
	"--trust-proxy": true,
	"--clipboard":   true,
	"-c":            true,
	"--metrics":     true,
}

// reorderFlags moves flag-like arguments (starting with "-") before
// positional arguments so Go's flag package parses them correctly.
// Go's stdlib flag.Parse stops at the first non-flag argument, which
// means `cmd <positional> -flag val` silently ignores -flag. Most
// CLIs (git, docker, kubectl, gh) allow flags in any position.
func reorderFlags(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			// Boolean flags don't consume the next argument as a value
			if !boolFlags[args[i]] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positional = append(positional, args[i])
		}
	}
	return append(flags, positional...)
}
