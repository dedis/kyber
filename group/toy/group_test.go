package toy

import (
	"testing"

	"github.com/dedis/kyber/util/test"
	"github.com/dedis/kyber/xof/blake2xb"
)

func TestToyGroup(t *testing.T) {
	seed := []byte{42}
	test.GroupTest(t, Group, blake2xb.New(seed[:]))
}
