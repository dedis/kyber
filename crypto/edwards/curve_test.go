package edwards

import (
	"testing"
	"dissent/crypto"
)

func TestBasicCurve25519(t *testing.T) {
	crypto.TestGroup(new(basicCurve).init25519())
}

func TestBasicCurveE382(t *testing.T) {
	crypto.TestGroup(new(basicCurve).initE382())
}

func TestBasicCurve41417(t *testing.T) {
	crypto.TestGroup(new(basicCurve).init41417())
}

func TestBasicCurveE521(t *testing.T) {
	crypto.TestGroup(new(basicCurve).initE521())
}

