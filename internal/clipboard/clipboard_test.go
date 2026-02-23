package clipboard

import (
	"runtime"
	"testing"
)

func TestCommand(t *testing.T) {
	name, _ := command()
	switch runtime.GOOS {
	case "darwin":
		if name != "pbcopy" {
			t.Fatalf("expected pbcopy on darwin, got %q", name)
		}
	case "windows":
		if name != "clip.exe" {
			t.Fatalf("expected clip.exe on windows, got %q", name)
		}
	case "linux":
		// May or may not have xclip/xsel installed
		if name != "" && name != "xclip" && name != "xsel" {
			t.Fatalf("unexpected clipboard command on linux: %q", name)
		}
	}
}

func TestAvailable(t *testing.T) {
	// On macOS and Windows, clipboard should always be available.
	// On Linux CI, it may not be.
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		if !Available() {
			t.Fatal("expected clipboard to be available on", runtime.GOOS)
		}
	}
}

func TestWriteRoundTrip(t *testing.T) {
	if !Available() {
		t.Skip("no clipboard utility available")
	}
	// Write a known value and verify no error.
	// We don't read back to avoid depending on pbpaste/xclip -o.
	if err := Write([]byte("zkettle-clipboard-test")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
}
