package edwards25519

import (
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestVartime(t *testing.T) {
	p := tSuite.Point()
	if pvt, ok := p.(kyber.AllowsVarTime); ok {
		// Try both settings
		pvt.AllowVarTime(false)
		p.Mul(one, p)
		pvt.AllowVarTime(true)
		p.Mul(one, p)
	} else {
		t.Fatal("expected Point to allow var time")
	}
}
