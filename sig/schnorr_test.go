package sig

import (
	"github.com/dedis/crypto/suite"
	"testing"
)

func TestSignVerify(t *testing.T) {
	TestScheme(t, SchnorrScheme{Suite: suites.Default})
}
