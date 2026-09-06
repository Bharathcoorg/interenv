package interenv

import "testing"

func TestDiscoverBinary(t *testing.T) {
	bin := discoverBinary()
	if bin == "" {
		t.Fatal("expected non-empty binary name")
	}
}
