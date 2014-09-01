package edwards

import (
	"testing"
	"dissent/crypto"
)


// Test ProjectiveCurve versus BasicCurve implementations

func TestProjective25519(t *testing.T) {
	crypto.TestCompareGroups(
		new(BasicCurve).init25519(),
		new(ProjectiveCurve).Init(Param25519()))
}

func TestProjectiveE382(t *testing.T) {
	crypto.TestCompareGroups(
		new(BasicCurve).Init(ParamE382()),
		new(ProjectiveCurve).Init(ParamE382()))
}

func TestProjective41417(t *testing.T) {
	crypto.TestCompareGroups(
		new(BasicCurve).Init(Param41417()),
		new(ProjectiveCurve).Init(Param41417()))
}

func TestProjectiveE521(t *testing.T) {
	crypto.TestCompareGroups(
		new(BasicCurve).Init(ParamE521()),
		new(ProjectiveCurve).Init(ParamE521()))
}

// Test ExtendedCurve versus ProjectiveCurve implementations

func TestExtended25519(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(Param25519()),
		new(ExtendedCurve).Init(Param25519()))
}

func TestExtendedE382(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(ParamE382()),
		new(ExtendedCurve).Init(ParamE382()))
}

func TestExtended41417(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(Param41417()),
		new(ExtendedCurve).Init(Param41417()))
}

func TestExtendedE521(t *testing.T) {
	crypto.TestCompareGroups(
		new(ProjectiveCurve).Init(ParamE521()),
		new(ExtendedCurve).Init(ParamE521()))
}

