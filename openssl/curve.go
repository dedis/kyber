// +build experimental

package openssl

// #include <openssl/ec.h>
// #include <openssl/bn.h>
// #include <openssl/obj_mac.h>
//
// struct bignum_ctx {
// };
//
// struct ec_group_st {		// CGo doesn't like undefined C structs
// };
//
// struct ec_point_st {
// };
//
import "C"

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/group"
	"math/big"
)

type curve struct {
	ctx          *_Ctype_struct_bignum_ctx
	g            *_Ctype_struct_ec_group_st
	p, n, cofact *bignum
	plen, nlen   int
	name         string
	null         *point
}

func (c *curve) String() string {
	return c.name
}

func (c *curve) PrimeOrder() bool {
	return true // we only support the NIST prime-order curves
}

func (c *curve) ScalarLen() int {
	return c.nlen
}

func (c *curve) Scalar() group.FieldElement {
	return newScalar(c)
}

func (c *curve) ElementLen() int {
	return 1 + c.plen // compressed encoding
}

func (c *curve) Element() group.Element {
	return newPoint(c)
}

func (c *curve) Order() *big.Int {
	return c.n.BigInt()
}

func (c *curve) initNamedCurve(name string, nid C.int) *curve {
	c.name = name

	c.ctx = C.BN_CTX_new()
	if c.ctx == nil {
		panic("C.BN_CTX_new: " + getErrString())
	}

	c.g = C.EC_GROUP_new_by_curve_name(nid)
	if c.g == nil {
		panic("can't find create P256 curve: " + getErrString())
	}

	// Get this curve's prime field
	c.p = newBigNum()
	if C.EC_GROUP_get_curve_GFp(c.g, c.p.bn, nil, nil, c.ctx) == 0 {
		panic("EC_GROUP_get_curve_GFp: " + getErrString())
	}
	c.plen = (c.p.BitLen() + 7) / 8

	// Get the curve's group order
	c.n = newBigNum()
	if C.EC_GROUP_get_order(c.g, c.n.bn, c.ctx) == 0 {
		panic("EC_GROUP_get_order: " + getErrString())
	}
	c.nlen = (c.n.BitLen() + 7) / 8

	// Get the curve's cofactor
	c.cofact = newBigNum()
	if C.EC_GROUP_get_cofactor(c.g, c.cofact.bn, c.ctx) == 0 {
		panic("EC_GROUP_get_cofactor: " + getErrString())
	}

	// Stash a copy of the point at infinity
	c.null = newPoint(c)
	c.null.Zero()

	return c
}

func (c *curve) initP224() group.Group {
	return c.initNamedCurve("P224", C.NID_secp224r1)
}

func (c *curve) initP256() group.Group {
	return c.initNamedCurve("P256", C.NID_X9_62_prime256v1)
}

func (c *curve) initP384() group.Group {
	return c.initNamedCurve("P384", C.NID_secp384r1)
}

func (c *curve) initP521() group.Group {
	return c.initNamedCurve("P521", C.NID_secp521r1)
}

// Create a context configured with the NIST P-224 elliptic curve.
func WithP224(parent abstract.Context) abstract.Context {
	return group.Context(parent, new(curve).initP224())
}

// Create a context configured with the NIST P-256 elliptic curve.
func WithP256(parent abstract.Context) abstract.Context {
	return group.Context(parent, new(curve).initP256())
}

// Create a context configured with the NIST P-384 elliptic curve.
func WithP384(parent abstract.Context) abstract.Context {
	return group.Context(parent, new(curve).initP384())
}

// Create a context configured with the NIST P-521 elliptic curve.
func WithP521(parent abstract.Context) abstract.Context {
	return group.Context(parent, new(curve).initP521())
}
