package main

// XXX get rid of mac-dependent paths below

// #include <sodium/crypto_scalarmult_curve25519.h>
// #cgo CFLAGS: -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lsodium
//

// #include "smult_curve25519_donna_c64.c"
//
import "C"

import (
	"unsafe"
	"math/big"
	"encoding/hex"
	"dissent/crypto"
)

func rand(b *[32]byte) {
	crypto.RandomStream.XORKeyStream(b[:],b[:])
}

func mult(q,n,p *[32]byte) {
	C.crypto_scalarmult(
		(*_Ctype_u8)(unsafe.Pointer(&q[0])),
		(*_Ctype_u8)(unsafe.Pointer(&n[0])),
		(*_Ctype_u8)(unsafe.Pointer(&p[0])))
}

func baseMult(q,n *[32]byte) {
/*
	C.crypto_scalarmult_base(
		(*C.uchar)(unsafe.Pointer(&q[0])),
		(*C.uchar)(unsafe.Pointer(&n[0])))
*/
	b := [32]byte{9}
	mult(q,n,&b)
}

func negBaseMult(q,n *[32]byte) {
/*
	C.crypto_scalarmult_base(
		(*C.uchar)(unsafe.Pointer(&q[0])),
		(*C.uchar)(unsafe.Pointer(&n[0])))
*/
	b := [32]byte{9}
	b[31] |= 0x80	// negate x-coord
	mult(q,n,&b)
}

func set(r *[32]byte, s string) {
	b,_ := hex.DecodeString(s)
	for i := range(r) {
		r[31-i] = b[i]
	}
}

func calcOrders() {
	four := new(big.Int).SetUint64(4)
	eight := new(big.Int).SetUint64(8)

	p1,_ := new(big.Int).SetString("27742317777372353535851937790883648493",
					10)
	p1.SetBit(p1, 252, 1)
	//println("p1",hex.EncodeToString(o1.Bytes()))
	//println("p1 prime",crypto.IsPrime(o1))
	o1 := new(big.Int).Mul(p1,eight)
	println("o1",hex.EncodeToString(o1.Bytes()))

	o2 := new(big.Int)
	o2.SetBit(o2, 253, 1)
	o3,_ := new(big.Int).SetString("55484635554744707071703875581767296995", 10)
	o2.Sub(o2,o3)
	//println("p2",hex.EncodeToString(o2.Bytes()))
	//println("p2 prime",crypto.IsPrime(o2))
	o2.Mul(o2,four)
	println("o2",hex.EncodeToString(o2.Bytes()))
}

func main() {
	calcOrders()

	var o1,o2 [32]byte
	set(&o1,"80000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f68")
	set(&o2,"7fffffffffffffffffffffffffffffff5908310ae843194d3f6ce72d18516074")

	var o1a,o1b [32]byte
	set(&o1a,"4000000000000000000000000000000000000000000000000000000000000008")
	set(&o1b,"40000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f68")


	var q,zero [32]byte

	baseMult(&q,&zero)
	println("b^zero",hex.EncodeToString(q[:]))

	one := [32]byte{1}
	baseMult(&q,&one)
	println("b^1",hex.EncodeToString(q[:]))
	negBaseMult(&q,&one)
	println("-b^1",hex.EncodeToString(q[:]))

	onem := [32]byte{}
	set(&onem,"40000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f68")
	baseMult(&q,&onem)
	println("b^1'",hex.EncodeToString(q[:]))
	negBaseMult(&q,&onem)
	println("-b^1'",hex.EncodeToString(q[:]))

	two := [32]byte{2}
	baseMult(&q,&two)
	println("b^2",hex.EncodeToString(q[:]))
	mult(&q,&two,&q)
	println("b^2^2",hex.EncodeToString(q[:]))

	four := [32]byte{4}
	baseMult(&q,&four)
	println("b^4",hex.EncodeToString(q[:]))
	mult(&q,&four,&q)
	println("b^4^4",hex.EncodeToString(q[:]))

	eight := [32]byte{8}
	baseMult(&q,&eight)
	println("^8",hex.EncodeToString(q[:]))

	baseMult(&q,&o1)
	println("^o1",hex.EncodeToString(q[:]))

	baseMult(&q,&o1a)
	println("^o1a",hex.EncodeToString(q[:]))
	mult(&q,&o1b,&q)
	println("^o1b",hex.EncodeToString(q[:]))

	baseMult(&q,&o2)
	println("^o2",hex.EncodeToString(q[:]))


	var p,s [32]byte
	rand(&s)
	println("s",hex.EncodeToString(s[:]))

	baseMult(&q,&s)
	println(">",hex.EncodeToString(q[:]))

	rand(&p)
	println("p",hex.EncodeToString(p[:]))
	mult(&q,&s,&p)
	println(">",hex.EncodeToString(q[:]))
}

