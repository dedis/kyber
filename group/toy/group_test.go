package toy

import (
	"testing"

	"github.com/dedis/kyber/util/test"
)

func TestToyGroup(t *testing.T) {
	test.GroupTest(t, Group)
}
