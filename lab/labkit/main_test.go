//go:build lab

package labkit_test

import (
	"os"
	"testing"

	"github.com/donaldsteele/telltale/lab/labkit"
)

func TestMain(m *testing.M) {
	os.Exit(labkit.Main(m))
}
