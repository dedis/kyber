package abstract

import (
	"io"
	"fmt"
	"strings"
	"reflect"
	"crypto/cipher"
	"encoding/binary"
)

/*
Encoding is a basic interface representing fixed-length (or known-length)
cryptographic objects or structures having a built-in binary encoding.
*/
type Encoding interface {
	String() string

	// Encoded length of this object in bytes.
	Len() int

	// Encode the content of this object into a slice,
	// whose length must be exactly Len().
	Encode() []byte

	// Encode the contents of this object and write it to an io.Writer.
	EncodeTo(w io.Writer) (int, error)

	// Decode the content of this object from a slice,
	// whose length must be exactly Len().
	Decode(buf []byte) error

	// Decode the content of this object by reading from an io.Reader.
	// If r is a Cipher, uses it to pick a valid object pseudo-randomly,
	// which may entail reading more than Len bytes due to retries.
	DecodeFrom(r io.Reader) (int, error)
}


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


// PointEncodeTo provides a generic implementation of Point.EncodeTo
// based on Point.Encode.
func PointEncodeTo(p Point, w io.Writer) (int, error) {
	return w.Write(p.Encode())
}

// PointDecodeFrom provides a generic implementation of Point.DecodeFrom,
// based on Point.Decode, or Point.Pick if r is a Cipher or cipher.Stream.
// The returned byte-count is valid only when decoding from a normal Reader,
// not when picking from a pseudorandom source.
func PointDecodeFrom(p Point, r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		p.Pick(nil, strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, p.Len())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.Decode(buf)
}

// SecretEncodeTo provides a generic implementation of Secret.EncodeTo
// based on Secret.Encode.
func SecretEncodeTo(s Secret, w io.Writer) (int, error) {
	return w.Write(s.Encode())
}

// SecretDecodeFrom provides a generic implementation of Secret.DecodeFrom,
// based on Secret.Decode, or Secret.Pick if r is a Cipher or cipher.Stream.
// The returned byte-count is valid only when decoding from a normal Reader,
// not when picking from a pseudorandom source.
func SecretDecodeFrom(s Secret, r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		s.Pick(strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, s.Len())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.Decode(buf)
}



// Not used other than for reflect.TypeOf()
var aSecret Secret
var aPoint Point

var tSecret = reflect.TypeOf(&aSecret).Elem()
var tPoint = reflect.TypeOf(&aPoint).Elem()


func prindent(depth int, format string, a ...interface{}) {
	fmt.Print(strings.Repeat("  ",depth))
	fmt.Printf(format, a...)
}


type decoder struct {
	g Group
	r io.Reader
}

func Read(r io.Reader, obj interface{}, g Group) error {
	de := decoder{g,r}
	return de.value(reflect.ValueOf(obj),0)
}

func (de *decoder) value(v reflect.Value, depth int) error {

	// Does the value need to be instantiated?
	obj := v.Interface()
	if false { //obj == nil {
		println("v: "+v.String())
		println("t: "+v.Type().String())
		println("s: ",v.CanSet())
		println("sec:",v.Type() == tSecret)
		println("pt:",v.Type() == tPoint)

		switch v.Type() {
		case tSecret:
			//v.Set(reflect.ValueOf(de.g.Secret()))
			;
		case tPoint:
			v.Set(reflect.ValueOf(de.g.Point()))
		default:
			panic("unsupported null pointer type: "+
				v.Type().String())
		}
		println("r: ",v.String())
		println("o: ",v.Interface())
		obj = v.Interface()
	}

	// Does the object support our self-decoding interface?
	if e,ok := obj.(Encoding); ok {
		_, err := e.DecodeFrom(de.r)
		//prindent(depth, "decode: %s\n", e.String())
		return err
	}

	// Otherwise, reflectively handle composite types.
	//prindent(depth, "%s: %s\n", v.Kind().String(), v.Type().String())
	switch v.Kind() {

	case reflect.Interface:
		if v.IsNil() {
			// See if we can auto-fill certain interface variables
			t := v.Type()
			switch t {
			case tSecret:
				v.Set(reflect.ValueOf(de.g.Secret()))
			case tPoint:
				v.Set(reflect.ValueOf(de.g.Point()))
			default:
				panic("unsupported null pointer type: "+
					t.String())
			}
		}
		fallthrough
	case reflect.Ptr:
		if v.IsNil() {
			panic("null pointer")
		}
		return de.value(v.Elem(),depth+1)

	case reflect.Struct:
		l := v.NumField()
		for i := 0; i < l; i++ {
			if err := de.value(v.Field(i),depth+1); err != nil {
				return err
			}
		}

	case reflect.Array:
	case reflect.Slice:
		l := v.Len()
		for i := 0; i < l; i++ {
			if err := de.value(v.Index(i),depth+1); err != nil {
				return err
			}
		}

	default:
		// Fall back to big-endian binary encoding
		return binary.Read(de.r, binary.BigEndian, obj)
	}
	return nil
}


type encoder struct {
	g Group
	w io.Writer
}

// Write a data structure containing cryptographic objects,
// using their built-in binary serialization, to an io.Writer.
// Supports writing of Points, Secrets,
// basic fixed-length data types supported by encoding/binary/Write(),
// and structs, arrays, and slices containing all of these types.
func Write(w io.Writer, obj interface{}, g Group) error {
	en := encoder{g,w}
	return en.value(obj, 0)
}

func (en *encoder) value(obj interface{}, depth int) error {

	// Does the object support our self-decoding interface?
	if e,ok := obj.(Encoding); ok {
		//prindent(depth, "encode: %s\n", e.String())
		_, err := e.EncodeTo(en.w)
		return err
	}

	// Otherwise, reflectively handle composite types.
	v := reflect.ValueOf(obj)
	//prindent(depth, "%s: %s\n", v.Kind().String(), v.Type().String())
	switch v.Kind() {

	case reflect.Interface:
	case reflect.Ptr:
		return en.value(v.Elem().Interface(), depth+1)

	case reflect.Struct:
		l := v.NumField()
		for i := 0; i < l; i++ {
			if err := en.value(v.Field(i).Interface(), depth+1); err != nil {
				return err
			}
		}

	case reflect.Array:
	case reflect.Slice:
		l := v.Len()
		for i := 0; i < l; i++ {
			if err := en.value(v.Index(i).Interface(), depth+1); err != nil {
				return err
			}
		}

	default:
		// Fall back to big-endian binary encoding
		return binary.Write(en.w, binary.BigEndian, obj)
	}
	return nil
}

