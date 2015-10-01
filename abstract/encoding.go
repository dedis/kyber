package abstract

import (
	"crypto/cipher"
	"io"
	"reflect"
	"github.com/dedis/crypto/marshal"
)


// Not used other than for reflect.TypeOf()
var aSecret Secret
var aPoint Point

var tSecret = reflect.TypeOf(&aSecret).Elem()
var tPoint = reflect.TypeOf(&aPoint).Elem()


/*
Hiding is an alternative encoding interface to encode cryptographic objects
such that their representation appears indistinguishable from a
uniformly random byte-string.

Achieving uniformity in representation is challenging for elliptic curves.
For this reason, the Hiding-encoding of an elliptic curve point
is typically more costly to compute than the normal (non-hidden) encoding,
may be less space efficient,
and may not allow representation for all possible curve points.
This interface allows the ciphersuite to determine
the specific uniform encoding method and balance their tradeoffs.
Since some uniform encodings cannot represent all possible points,
the caller must be prepared to call HideEncode() in a loop
with a freshly-chosen object (typically a fresh Diffie-Hellman public key).

For further background and technical details:

	"Elligator: Elliptic-curve points indistinguishable from uniform random strings"
	http://elligator.cr.yp.to/elligator-20130828.pdf
	"Elligator Squared: Uniform Points on Elliptic Curves of Prime Order as Uniform Random Strings"
	http://eprint.iacr.org/2014/043.pdf
	"Binary Elligator squared"
	http://eprint.iacr.org/2014/486.pdf
*/
type Hiding interface {

	// Hiding-encoded length of this object in bytes.
	HideLen() int

	// Attempt to encode the content of this object into a slice,
	// whose length must be exactly HideLen(),
	// using a specified source of random bits.
	// Encoding may consistently fail on some curve points,
	// in which case this method returns nil,
	// and the caller must try again after re-randomizing the object.
	HideEncode(rand cipher.Stream) []byte

	// Decode a uniform representation of this object from a slice,
	// whose length must be exactly HideLen().
	// This method cannot fail on correctly-sized input:
	// it maps every HideLen()-byte string to some object.
	// This is a necessary security property,
	// since if some correctly-sized byte strings failed to decode,
	// an attacker could use decoding as a hidden object detection test.
	HideDecode(buf []byte)
}

// Default implementation of reflective constructor for ciphersuites
func SuiteNew(s Suite, t reflect.Type) interface{} {
	switch t {
	case tSecret:
		return s.Secret()
	case tPoint:
		return s.Point()
	}
	return nil
}

// Default implementation of Encoding interface Read for ciphersuites
func SuiteRead(s Suite, r io.Reader, objs ...interface{}) error {
	return marshal.BinaryEncoding{Constructor: s}.Read(r, objs...)
}

// Default implementation of Encoding interface Write for ciphersuites
func SuiteWrite(s Suite, w io.Writer, objs ...interface{}) error {
	return marshal.BinaryEncoding{Constructor: s}.Write(w, objs...)
}
