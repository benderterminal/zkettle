package outfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommitWritesWith0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	out, err := Reserve(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Abort()
	if err := out.Commit([]byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	out.Abort() // must not remove a committed file

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hunter2" {
		t.Fatalf("got %q", data)
	}
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %o, want 600", perm)
	}
}

func TestReserveRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(path); err == nil {
		t.Fatal("expected error for existing file")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "keep me" {
		t.Fatalf("existing file was modified: %q", data)
	}
}

func TestAbortRemovesUncommittedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.txt")
	out, err := Reserve(path)
	if err != nil {
		t.Fatal(err)
	}
	out.Abort()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("reserved file not removed: %v", err)
	}
}

func TestReserveBadPath(t *testing.T) {
	if _, err := Reserve(filepath.Join(t.TempDir(), "missing-dir", "f")); err == nil {
		t.Fatal("expected error for missing directory")
	}
}
