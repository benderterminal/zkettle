package clipboard

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
)

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

func Available() bool {
	name, _ := command()
	return name != ""
}

func Write(data []byte) error {
	name, args := command()
	if name == "" {
		return fmt.Errorf("no clipboard utility found (install pbcopy, xclip, or xsel)")
	}

	cmd := exec.Command(name, args...)
	cmd.Stdin = bytes.NewReader(data)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clipboard write failed: %w", err)
	}
	return nil
}
