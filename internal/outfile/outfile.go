// Package outfile writes a decrypted secret to a new file.
package outfile

import (
	"fmt"
	"os"
)

// File is an output file reserved before the secret is fetched, so a bad path
// fails without consuming a view.
type File struct {
	f         *os.File
	committed bool
}

// Reserve creates path with 0600 permissions. It refuses to overwrite an
// existing file, which would also keep that file's looser permissions.
func Reserve(path string) (*File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("output file %s already exists (refusing to overwrite)", path)
		}
		return nil, fmt.Errorf("creating output file: %w", err)
	}
	return &File{f: f}, nil
}

// Commit writes data and closes the file.
func (o *File) Commit(data []byte) error {
	if _, err := o.f.Write(data); err != nil {
		return fmt.Errorf("writing to file: %w", err)
	}
	if err := o.f.Close(); err != nil {
		return fmt.Errorf("writing to file: %w", err)
	}
	o.committed = true
	return nil
}

// Abort removes the reserved file unless it was committed. Safe to defer.
func (o *File) Abort() {
	if o.committed {
		return
	}
	o.f.Close()
	os.Remove(o.f.Name())
}
