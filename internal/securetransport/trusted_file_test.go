package securetransport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadTrustedFileRejectsSymlinkedLeafAndParent(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(dir, "leaf.txt")
	if err := os.Symlink(outside, leaf); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ReadTrustedFile(leaf); err == nil {
		t.Fatal("ReadTrustedFile accepted a symlinked leaf")
	}
	linkedDir := filepath.Join(dir, "linked")
	if err := os.Symlink(filepath.Dir(outside), linkedDir); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	if _, err := ReadTrustedFile(filepath.Join(linkedDir, filepath.Base(outside))); err == nil {
		t.Fatal("ReadTrustedFile accepted a symlinked parent")
	}
}

func TestOpenTrustedFileAllowsNewRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	f, err := OpenTrustedFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
}
