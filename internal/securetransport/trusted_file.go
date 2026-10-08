package securetransport

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// OpenTrustedFile opens an operator-configured path after checking that its
// parent and, when present, the leaf are not symlinks. It is used for both
// read-only configuration and files created beneath an operator-selected
// runtime directory.
func OpenTrustedFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	abs, err := trustedPath(path)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(abs)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, err
	}
	if resolvedParent != parent {
		return nil, errors.New("symlinked configuration parent is not trusted")
	}
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("symlinked configuration paths are not trusted")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(abs, flags, mode) // #nosec G304 -- parent and leaf are checked for symlink escapes above.
	if err != nil {
		return nil, err
	}
	return f, nil
}

// ReadTrustedFile reads an operator-configured file only when every path
// component is non-symlinked. Configuration paths are exact files, not path
// templates; rejecting symlinks prevents an attacker from redirecting a
// trusted configuration reference outside the operator-selected location.
func ReadTrustedFile(path string) ([]byte, error) {
	abs, err := trustedPath(path)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	if resolved != abs {
		return nil, errors.New("symlinked configuration paths are not trusted")
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configured path is not a regular file")
	}
	f, err := OpenTrustedFile(abs, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func trustedPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("file path is required")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	return abs, nil
}
