package edwards

import (
	"testing"
	"dissent/crypto"
)


// Test basicCurve and projCurve implementations

func Test25519(t *testing.T) {
	crypto.TestCompareGroups(
		new(basicCurve).init25519(),
		new(projCurve).init(Param25519()))
}

func TestE382(t *testing.T) {
	crypto.TestCompareGroups(
		new(basicCurve).init(ParamE382()),
		new(projCurve).init(ParamE382()))
}

func Test41417(t *testing.T) {
	crypto.TestCompareGroups(
		new(basicCurve).init(Param41417()),
		new(projCurve).init(Param41417()))
}

func TestE521(t *testing.T) {
	crypto.TestCompareGroups(
		new(basicCurve).init(ParamE521()),
		new(projCurve).init(ParamE521()))
}

