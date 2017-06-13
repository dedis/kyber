package pbc

import (
	"fmt"
	"testing"

	"gopkg.in/dedis/kyber.v1/util/test"

	"github.com/stretchr/testify/require"
)

func TestPrintConstants(t *testing.T) {
	t.Skip("test generating the generators")
	var p0 = NewPairingFp254BNb()
	p0g1 := p0.G1().Point().(*PointG1)
	printSeed(Fp254_G1_Base_Seed, &p0g1.g, t)
	p0g2 := p0.G2().Point().(*PointG2)
	printSeed(Fp254_G2_Base_Seed, &p0g2.g, t)

	fmt.Println()
	var p1 = NewPairingFp382_1()
	p1g1 := p1.G1().Point().(*PointG1)
	printSeed(Fp382_1_G1_Base_Seed, &p1g1.g, t)
	p1g2 := p1.G2().Point().(*PointG2)
	printSeed(Fp382_1_G2_Base_Seed, &p1g2.g, t)

	fmt.Println()
	var p2 = NewPairingFp382_2()
	p2g1 := p2.G1().Point().(*PointG1)
	printSeed(Fp382_2_G1_Base_Seed, &p2g1.g, t)
	p2g2 := p2.G2().Point().(*PointG2)
	printSeed(Fp382_2_G2_Base_Seed, &p2g2.g, t)

}

type hashmap interface {
	HashAndMapTo([]byte) error
	GetString(int) string
}

func printSeed(name string, h hashmap, t *testing.T) {
	err := h.HashAndMapTo([]byte(name))
	require.Nil(t, err)
	fmt.Println(name + " : " + h.GetString(16))
}

func TestFailing(t *testing.T) {
	var p2 = NewPairingFp382_2()
	g2 := p2.G2()
	ptmp := g2.Point()
	stmp := g2.Scalar()
	rgen := g2.Point()

	//rgen = rgen.Pick(random.Stream)
	require.Nil(t, rgen.(*PointG2).g.SetString("1 18d3d8c085a5a5e7553c3a4eb628e88b8465bf4de2612e35a0a4eb018fb0c82e9698896031e62fd7633ffd824a859474 1dc6edfcf33e29575d4791faed8e7203832217423bf7f7fbf1f6b36625b12e7132c15fbc15562ce93362a322fb83dd0d 65836963b1f7b6959030ddfa15ab38ce056097e91dedffd996c1808624fa7e2644a77be606290aa555cda8481cfb3cb 1b77b708d3d4f65aeedf54b58393463a42f0dc5856baadb5ce608036baeca398c5d9e6b169473a8838098fd72fd28b50", 16))
	//rgen = rgen.Base()
	stmp = stmp.SetInt64(-1)
	ptmp = ptmp.Mul(stmp, rgen) // ptmp = (-1) * rgen
	ptmp = ptmp.Add(ptmp, rgen) // ptmp = (-1) * rgen + rgen = 0
	if !ptmp.(*PointG2).g.IsZero() {
		print("H")
		t.Fail()
	}
	if !ptmp.Equal(g2.Point().Null()) {
		t.Fail()
	}
}

func TestG2(t *testing.T) {
	var p0 = NewPairingFp254BNb()
	g2 := p0.G2()
	q1 := g2.Point().Base()  // q1 = base
	q2 := g2.Point().Neg(q1) // q2 =  -base
	s1 := g2.Scalar().SetInt64(-1)
	q3 := g2.Point().Mul(s1, q1) // q3 = (-1) * base

	if !q2.Equal(q3) {
		t.Fail()
	}

	q3.Add(q3, q1)
	if !q3.Equal(q2.Null()) {
		t.Fail()
	}

}

func TestP0(t *testing.T) {
	//var p0 = NewPairingFp254BNb()
	//test.TestGroup(p0.G1())
	//test.TestGroup(p0.G2())
	//test.TestGroup(p0.GT())
}

func TestP1(t *testing.T) {
	/*var p1 = NewPairingFp382_1()*/
	//test.TestGroup(p1.G1())
	/*test.TestGroup(p1.G2())*/
	//test.TestGroup(p1.GT())
}

func TestP2(t *testing.T) {
	var p2 = NewPairingFp382_2()
	test.TestGroup(p2.G2())
	test.TestGroup(p2.G1())
	//test.TestGroup(p2.GT())
}
