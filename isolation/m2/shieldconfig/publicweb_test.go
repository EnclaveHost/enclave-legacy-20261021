//go:build unix

package shieldconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublicWebMarked(t *testing.T) {
	dir := t.TempDir()
	me := os.Getuid()
	if ok, err := PublicWebMarked(filepath.Join(dir, "absent"), me); ok || err != nil {
		t.Fatalf("absent marker: %v %v", ok, err)
	}
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte("1\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if ok, err := PublicWebMarked(good, me); !ok || err != nil {
		t.Fatalf("read-only marker: %v %v", ok, err)
	}
	if ok, err := PublicWebMarked(good, me+1); ok || err == nil {
		t.Fatal("a marker owned by someone else must be an error")
	}
	writable := filepath.Join(dir, "writable")
	if err := os.WriteFile(writable, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, err := PublicWebMarked(writable, me); ok || err == nil {
		t.Fatal("a writable marker must be an error")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if ok, err := PublicWebMarked(link, me); ok || err == nil {
		t.Fatal("a symlinked marker must be an error")
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o555); err != nil {
		t.Fatal(err)
	}
	if ok, err := PublicWebMarked(filepath.Join(dir, "d"), me); ok || err == nil {
		t.Fatal("a directory marker must be an error")
	}
}
