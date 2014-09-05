// This package contains several implementations of Twisted Edwards Curves,
// from general and unoptimized to highly specialized and optimized.
//
// Twisted Edwards curves (TEC's) are elliptic curves satisfying the equation:
//
//	ax^2 + y^2 = c^2(1 + dx^2y^2)
//
// for some scalars c, d over some field K.
// We assume K is a (finite) prime field for a large prime p.
// We also assume c == 1 because all curves in the generalized form
// are isomorphic to curves having c == 1.
// For details see Bernstein et al, "Twisted Edwards Curves",
// http://eprint.iacr.org/2008/013.pdf
// 
package edwards

import (
	"math/big"
)


// Parameters defining a Twisted Edwards curve (TEC).
type Param struct {
	Name string		// Name of curve
	P big.Int		// Prime defining the underlying field
	R big.Int		// Prime order of the standard base point
	S big.Int		// Cofactor: R*S is total size of curve
	A,D big.Int		// Edwards curve equation parameters
	BX,BY big.Int		// Coordinate of standard base point
}

// Return the name of this curve.
func (p *Param) String() string {
	return p.Name
}


// Parameters defining the Edwards version of Curve25519, as specified in:
// Bernstein et al, "High-speed high-security signatures",
// http://ed25519.cr.yp.to/ed25519-20110926.pdf
//
func Param25519() *Param {
	var p Param
	var rs big.Int
	p.Name = "25519"
	p.P.SetBit(zero,255,1).Sub(&p.P,big.NewInt(19))
	rs.SetString("27742317777372353535851937790883648493",10)
	p.R.SetBit(zero,252,1).Add(&p.R,&rs)
	p.S.SetInt64(8)
	p.A.SetInt64(-1).Add(&p.P,&p.A)
	p.D.SetString("37095705934669439343138083508754565189542113879843219016388785533085940283555",10)
	p.BX.SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202",10)
	p.BY.SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960",10)
	return &p
}

// Parameters for the E-382 curve specified in:
// Aranha et al, "A note on high-security general-purpose elliptic curves",
// http://eprint.iacr.org/2013/647.pdf
//
// and more recently included in:
// Josefsson/Pegourie-Gonnard,
// "Additional Elliptic Curves for Transport Layer Security (TLS) Key Agreement",
// http://tools.ietf.org/html/draft-josefsson-tls-additional-curves-00
//
func ParamE382() *Param {
	var p Param
	var rs big.Int
	p.Name = "E382"
	p.P.SetBit(zero,382,1).Sub(&p.P,big.NewInt(105)) // p = 2^382-105
	rs.SetString("1030303207694556153926491950732314247062623204330168346855",10)
	p.R.SetBit(zero,380,1).Sub(&p.R,&rs)
	p.S.SetInt64(8)
	p.A.SetInt64(1)
	p.D.SetInt64(-67254)
	p.BX.SetString("3914921414754292646847594472454013487047137431784830634731377862923477302047857640522480241298429278603678181725699",10)
	p.BY.SetString("17",10)
	return &p
}

// Parameters for Curve41417, as specified in:
// Bernstein et al, "Curve41417: Karatsuba revisited",
// http://eprint.iacr.org/2014/526.pdf
func Param41417() *Param {
	var p Param
	var rs big.Int
	p.Name = "41417"
	p.P.SetBit(zero,414,1).Sub(&p.P,big.NewInt(17))
	rs.SetString("33364140863755142520810177694098385178984727200411208589594759",10)
	p.R.SetBit(zero,411,1).Sub(&p.R,&rs)
	p.S.SetInt64(8)
	p.A.SetInt64(1)
	p.D.SetInt64(3617)
	p.BX.SetString("17319886477121189177719202498822615443556957307604340815256226171904769976866975908866528699294134494857887698432266169206165",10)
	p.BY.SetString("34",10)
	return &p
}

// Parameters for the E-521 curve specified in:
// Aranha et al, "A note on high-security general-purpose elliptic curves",
// http://eprint.iacr.org/2013/647.pdf
//
// and more recently included in:
// Josefsson/Pegourie-Gonnard,
// "Additional Elliptic Curves for Transport Layer Security (TLS) Key Agreement",
// http://tools.ietf.org/html/draft-josefsson-tls-additional-curves-00
//
func ParamE521() *Param {
	var p Param
	var rs big.Int
	p.Name = "E521"
	p.P.SetBit(zero,521,1).Sub(&p.P,one)
	rs.SetString("337554763258501705789107630418782636071904961214051226618635150085779108655765",10)
	p.R.SetBit(zero,519,1).Sub(&p.R,&rs)
	p.S.SetInt64(8)
	p.A.SetInt64(1)
	p.D.SetInt64(-376014)
	p.BX.SetString("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324",10)
	p.BY.SetString("12",10)
	return &p
}

