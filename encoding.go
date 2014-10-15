package crypto

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

	// XXX EncodeTo(w io.Writer) error
	// XXX WriteTo(w io.Writer) (n,error)

	// Decode the content of this object from a slice,
	// whose length must be exactly Len().
	Decode(buf []byte) error

	// Decode the content of this object by reading from an io.Reader.
	// If r is also a cipher.Stream (e.g., a RandomReader),
	// then picks a valid object [pseudo-]randomly from that stream,
	// which may entail reading more than Len bytes due to retries.
	// XXX DecodeFrom(r io.Reader) error
	// XXX ReadFrom(w io.Writer) (n,error)
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

		// Special handling for decoding from [pseudo-]random streams
		if rand,ok := de.r.(cipher.Stream); ok {
			// Decoding from a random stream: use Pick() methods.
			// XXX normalize random-element-decoding API.
			//prindent(depth, "random\n")
			switch o := obj.(type) {
				case Secret:
					o.Pick(rand)
				case Point:
					o.Pick(nil, rand)
				default:
					panic("unsupported crypto object")
			}
			return nil
		}

		// Decode from a stream that's supposed to contain valid objects
		l := e.Len()
		b := make([]byte, l)
		if _,err := io.ReadFull(de.r, b); err != nil {
			return err
		}
		err := e.Decode(b)
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
		b := e.Encode()
		if _,err := en.w.Write(b); err != nil {
			return err
		}
		return nil
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

