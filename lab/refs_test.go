//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A bundle's clean-up removes only its own leftover build directories.
// Another bundle whose key starts with this one's (the same packages with a
// third-party repository trusted, "-t...") may be building at the same time:
// deleting its directory made its fetch-refs fail in CI.
func TestStaleBuildDirsAreThisBundlesOnly(t *testing.T) {
	root := t.TempDir()
	key := "ubuntu24.04-bffe4c02dcde8c23"
	own := ".building-" + key + "-2062315756"
	for _, d := range []string{
		own,
		".building-" + key + "-tc5dea9fb14b4-2062315756",
		".building-" + key + "-",
		key + "-tc5dea9fb14b4",
		".building-ubuntu24.04-0000000000000000-1",
	} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := staleBuildDirs(root, key)
	if want := []string{filepath.Join(root, own)}; !slices.Equal(got, want) {
		t.Errorf("stale build directories of %s:\n got %q\nwant %q", key, got, want)
	}
}
