package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRouterDirChecksum(t *testing.T) {
	dir := t.TempDir()
	if routerDirChecksum(filepath.Join(dir, "missing")) != "" {
		t.Fatal("expected empty checksum for a missing directory")
	}

	empty := routerDirChecksum(dir)
	if err := os.WriteFile(filepath.Join(dir, "a.yml"), []byte("url: http://a"), 0o644); err != nil {
		t.Fatal(err)
	}
	one := routerDirChecksum(dir)
	if one == empty {
		t.Fatal("checksum did not change after adding a file")
	}
	if routerDirChecksum(dir) != one {
		t.Fatal("checksum is not stable for unchanged contents")
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if routerDirChecksum(dir) != one {
		t.Fatal("checksum changed after adding a subdirectory, which ReloadRouters ignores")
	}
}

// Kubernetes updates ConfigMap/Secret volumes by writing a new timestamped directory and atomically swapping the
// ..data symlink; each key is a symlink through ..data.  The file names and mtimes seen in the mount never change.
func TestRouterDirChecksumConfigMapSwap(t *testing.T) {
	dir := t.TempDir()
	writeVersion := func(version, contents string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, version), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, version, "router.yml"), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(version, filepath.Join(dir, "..data_tmp")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
	}

	writeVersion("..v1", "url: http://first")
	if err := os.Symlink(filepath.Join("..data", "router.yml"), filepath.Join(dir, "router.yml")); err != nil {
		t.Fatal(err)
	}
	before := routerDirChecksum(dir)

	writeVersion("..v2", "url: http://second")
	if routerDirChecksum(dir) == before {
		t.Fatal("checksum did not change after the ..data symlink swap")
	}
}
