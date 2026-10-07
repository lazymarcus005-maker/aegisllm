package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzWALRecovery(f *testing.F) {
	f.Add([]byte("garbage"))
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "segment-00000001.wal"), data, 0600); err != nil {
			t.Fatal(err)
		}
		wal, err := OpenWAL(WALConfig{Dir: dir, HMACKey: []byte("fuzz-wal-key")})
		if wal != nil {
			_ = wal.Close()
		}
		_ = err
	})
}
