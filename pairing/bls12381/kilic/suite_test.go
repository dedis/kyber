package kilic

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"go.dedis.ch/kyber/v4/pairing"

	"go.dedis.ch/kyber/v4"
)

func TestVerifySigOnG1WithG2Domain(t *testing.T) {
	pk := "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e"
	sig := "9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0"
	round := uint64(1)

	suite := NewBLS12381Suite()

	pkb, _ := hex.DecodeString(pk)
	pubkeyP := suite.G2().Point()
	pubkeyP.UnmarshalBinary(pkb)
	sigb, _ := hex.DecodeString(sig)
	sigP := suite.G1().Point()
	sigP.UnmarshalBinary(sigb)
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, round)
	msg := h.Sum(nil)

	base := suite.G2().Point().Base().Clone()
	MsgP := suite.G1().Point().(kyber.HashablePoint).Hash(msg)
	if suite.ValidatePairing(MsgP, pubkeyP, sigP, base) {
		t.Fatalf("Should have failed to validate because of invalid domain")
	}

	// setting the wrong domain for G1 hashing
	suite.(*Suite).SetDomainG1(DefaultDomainG2())
	MsgP = suite.G1().Point().(kyber.HashablePoint).Hash(msg)
	if !suite.ValidatePairing(MsgP, pubkeyP, sigP, base) {
		t.Fatalf("Error validating pairing")
	}
}

func TestVerifySigOnG2(t *testing.T) {
	pk := "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"
	sig := "8d61d9100567de44682506aea1a7a6fa6e5491cd27a0a0ed349ef6910ac5ac20ff7bc3e09d7c046566c9f7f3c6f3b10104990e7cb424998203d8f7de586fb7fa5f60045417a432684f85093b06ca91c769f0e7ca19268375e659c2a2352b4655"
	prevSig := "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a"
	round := uint64(1)

	suite := NewBLS12381Suite()
	pkb, _ := hex.DecodeString(pk)
	pubkeyP := suite.G1().Point()
	pubkeyP.UnmarshalBinary(pkb)
	sigb, _ := hex.DecodeString(sig)
	sigP := suite.G2().Point()
	sigP.UnmarshalBinary(sigb)
	prev, _ := hex.DecodeString(prevSig)
	h := sha256.New()
	h.Write(prev)
	_ = binary.Write(h, binary.BigEndian, round)
	msg := h.Sum(nil)

	base := suite.G1().Point().Base().Clone()
	MsgP := suite.G2().Point().(kyber.HashablePoint).Hash(msg)
	if !suite.ValidatePairing(base, sigP, pubkeyP, MsgP) {
		t.Fatalf("Error validating pairing")
	}
}

func TestImplementInterfaces(_ *testing.T) {
	var _ kyber.Point = &G1Elt{}
	var _ kyber.Point = &G2Elt{}
	var _ kyber.Point = &GTElt{}
	var _ kyber.HashablePoint = &G1Elt{}
	var _ kyber.HashablePoint = &G2Elt{}
	// var _ kyber.hashablePoint = &KyberGT{} // GT is not hashable for now
	var _ kyber.Group = &groupBls{}
	var _ pairing.Suite = &Suite{}
}

func TestSuiteWithDST(t *testing.T) {
	pk := "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e"
	sig := "9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0"
	round := uint64(1)
	// using DomainG2 for G1
	suite := NewBLS12381SuiteWithDST(DefaultDomainG2(), nil)

	pkb, _ := hex.DecodeString(pk)
	pubkeyP := suite.G2().Point()
	pubkeyP.UnmarshalBinary(pkb)
	sigb, _ := hex.DecodeString(sig)
	sigP := suite.G1().Point()
	sigP.UnmarshalBinary(sigb)
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, round)
	msg := h.Sum(nil)

	base := suite.G2().Point().Base().Clone()
	MsgP := suite.G1().Point().(kyber.HashablePoint).Hash(msg)
	if !suite.ValidatePairing(MsgP, pubkeyP, sigP, base) {
		t.Fatalf("Error validating pairing")
	}
}

func TestExplicitDefaultDST(t *testing.T) {
	g1d1 := NullG1([]byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")...)
	g2d1 := NullG2([]byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")...)
	g1d2 := NullG1([]byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")...)
	g2d2 := NullG2([]byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")...)

	if g1d1.dst != nil {
		t.Fatal("Default G1 DST should be represented internally as nil. Got:", string(g1d1.dst))
	}
	if g2d2.dst != nil {
		t.Fatal("Default G2 DST should be represented internally as nil. Got:", string(g2d2.dst))
	}
	if !bytes.Equal(g1d2.dst, domainG2) {
		t.Fatal("Non-default G1 DST should not be nil. Got:", string(g1d2.dst))
	}
	if !bytes.Equal(g2d1.dst, domainG1) {
		t.Fatal("Non-default G2 DST should not be nil. Got:", string(g2d1.dst))
	}

	suite := NewBLS12381SuiteWithDST(DefaultDomainG2(), DefaultDomainG2())
	sg1 := suite.G1().Point()
	sg2 := suite.G2().Point()
	if p, ok := sg1.(*G1Elt); !ok || !bytes.Equal(p.dst, domainG2) {
		t.Fatal("Non-default G1 DST should not be nil. Got:", string(p.dst))
	}
	if p, ok := sg2.(*G2Elt); !ok || p.dst != nil {
		t.Fatal("Default G2 DST should be represented internally as nil. Got:", string(p.dst))
	}
}
