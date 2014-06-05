package main

import (
	"crypto/sha256"
	"code.google.com/p/go.crypto/curve25519"
)



type CipherSuite interface {
	HashLen() int
	Hash(data []byte) []byte

	CurveBase(data []byte) []byte
	CurveMul(in, base []byte) []byte
}

type CipherSuite1 struct {
} 

func (cs CipherSuite1) HashLen() int { return sha256.Size }
func (cs CipherSuite1) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (cs CipherSuite1) CurveBase(data []byte) []byte {
	// XXX may well not be this simple...
	return cs.Hash(data)
}
func (cs CipherSuite1) CurveMul(in, base []byte) []byte {
	var ina, bsa [32]byte
	copy(ina[:],in)
	copy(bsa[:],base)
	var dsta [32]byte
	curve25519.ScalarMult(&dsta, &ina, &bsa)
	return dsta[:]
}

type CS1Point struct {
	u [32]byte
}

/*
func (p CS1Point) Mul(in []byte) Point {
	var dst Point
	curve25519.ScalarMult...
}
*/

