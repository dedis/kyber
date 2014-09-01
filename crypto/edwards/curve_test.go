package edwards

import (
	"testing"
	"dissent/crypto"
)


// Test BasicCurve and ProjectiveCurve implementations

func Test25519(t *testing.T) {
	crypto.TestCompareGroups(
		new(BasicCurve).init25519(),
		new(ProjectiveCurve).Init(Param25519()))
}

func TestE382(t *testing.T) {
	crypto.TestCompareGroups(
		new(BasicCurve).Init(ParamE382()),
		new(ProjectiveCurve).Init(ParamE382()))
}

func Test41417(t *testing.T) {
	crypto.TestCompareGroups(
		new(BasicCurve).Init(Param41417()),
		new(ProjectiveCurve).Init(Param41417()))
}

func TestE521(t *testing.T) {
	crypto.TestCompareGroups(
		new(BasicCurve).Init(ParamE521()),
		new(ProjectiveCurve).Init(ParamE521()))
}

