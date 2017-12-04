package random

import "testing"

func TestTestableNotAllowed(t *testing.T) {
	if testableRand {
		t.Fatal("testableRand must never be checked in true")
	}
}
