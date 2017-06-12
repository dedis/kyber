package pbc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

/*var p1 = NewPairingFp382_1()*/
/*var p2 = NewPairingFp382_2()*/

func TestPrintConstants(t *testing.T) {
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

/*func TestP0(t *testing.T) {*/
//test.TestGroup(p0.G1())
//test.TestGroup(p0.G2())
//test.TestGroup(p0.GT())
//}

/*func TestP1(t *testing.T) {*/
//test.TestGroup(p1.G1())
//test.TestGroup(p1.G2())
//test.TestGroup(p1.GT())
//}

//func TestP2(t *testing.T) {
//test.TestGroup(p2.G1())
//test.TestGroup(p2.G2())
//test.TestGroup(p2.GT())
/*}*/
