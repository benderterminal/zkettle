package clipboard

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// command returns the clipboard write command for the current platform.
// Returns empty strings if no clipboard utility is available.
func command() (name string, args []string) {
	switch runtime.GOOS {
	case "darwin":
		return "pbcopy", nil
	case "linux":
		if _, err := exec.LookPath("xclip"); err == nil {
			return "xclip", []string{"-selection", "clipboard"}
		}
		if _, err := exec.LookPath("xsel"); err == nil {
			return "xsel", []string{"--clipboard", "--input"}
		}
	case "windows":
		return "clip.exe", nil
	}
	return "", nil
}

// Available reports whether a clipboard write command exists on this system.
func Available() bool {
	name, _ := command()
	return name != ""
}

// Write copies text to the system clipboard.
func Write(text string) error {
	name, args := command()
	if name == "" {
		return fmt.Errorf("no clipboard utility found (install pbcopy, xclip, or xsel)")
	}

	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clipboard write failed: %w", err)
	}
	return nil
}
