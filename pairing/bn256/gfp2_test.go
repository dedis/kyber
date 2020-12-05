package bn256

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGfP2Norm(t *testing.T) {
	p := &gfP2{*newGFp(7), *newGFp(18)}
	expectednorm := *newGFp(7*7 + 18*18)
	var norm gfP
	norm.Norm(p)
	if norm != expectednorm {
		t.Error("Norm mismatch")
	}
}

func TestGfP2Power(t *testing.T) {
	a := &gfP2{gfP{2}, gfP{3}}
	ap := &gfP2{}
	a = gfP2Encode(a)

	// The characteristic p
	p := [4]uint64{0x185cac6c5e089667, 0xee5b88d120b5b59e, 0xaa6fecb86184dc21, 0x8fb501e34aa387f9}

	// Verify that a^p is the conjugate of a; that is, that a^p + a = 2 * Re(a)
	ap.Power(a, p)
	ap.Add(ap, a)
	apd := gfP2Decode(ap)
	require.Equal(t, apd, &gfP2{gfP{0}, gfP{6}})

	// Two arbitrary exponents
	r := [4]uint64{0x123456789abcdef0, 0x2468ace013579bdf, 0x89abcdef01234567, 0x13579bdf2468ace0}
	s := [4]uint64{0x1122334455667788, 0x99aabbccddeeff00, 0x159d26ae37bf48c0, 0x0c84fb73ea62d951}

	// Their sum r+s
	rps := [4]uint64{0x235689bcf0235678, 0xbe1368acf1469adf, 0x9f48f49d38e28e27, 0x1fdc97530ecb8631}

	// Verify that (a^r)*(a^s) = a^(r+s)
	ar := &gfP2{}
	as := &gfP2{}
	arps := &gfP2{}
	aras := &gfP2{}
	ar.Power(a, r)
	as.Power(a, s)
	arps.Power(a, rps)
	aras.Mul(ar, as)
	require.Equal(t, aras, arps)

	// Verify that (a^r)^s = (a^s)^r
	ars := &gfP2{}
	asr := &gfP2{}
	ars.Power(ar, s)
	asr.Power(as, r)
	require.Equal(t, ars, asr)
}

func testsqrt(t *testing.T, a *gfP2) {
	// A quadratic nonresidue
	nonresidue := &gfP2{*newGFp(1), *newGFp(2)}
	s := &gfP2{}

	r := s.Sqrt(a)
	if r == nil {
		// Not a quadratic residue, but then nonresidue*a will be one
		a.Mul(a, nonresidue)
		r = s.Sqrt(a)
	}

	if r == nil {
		t.Error("Neither a nor nonresidue*a is a quadratic residue")
	} else {
		s2 := &gfP2{}
		s2.Mul(s, s)
		if !s2.Equals(a) {
			t.Error("Sqrt mismatch")
		}
	}
}

func TestGfP2Sqrt(t *testing.T) {
	// Simple cases
	testsqrt(t, &gfP2{*newGFp(0), *newGFp(0)})
	testsqrt(t, &gfP2{*newGFp(0), *newGFp(1)})
	testsqrt(t, &gfP2{*newGFp(1), *newGFp(0)})
	testsqrt(t, &gfP2{*newGFp(0), *newGFp(-1)})

	// Two tests of the alpha = -1 branch
	testsqrt(t, &gfP2{*newGFp(0), *newGFp(-1)})
	testsqrt(t, &gfP2{*newGFp(0), *newGFp(13)})

	// Some other arbitrary tests, including a nonresidue
	testsqrt(t, &gfP2{*newGFp(2), *newGFp(-41)})
	testsqrt(t, &gfP2{*newGFp(2), *newGFp(-10)})
}
