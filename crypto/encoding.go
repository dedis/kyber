package crypto

import (
	"io"
	"reflect"
	"encoding/binary"
)

/*
Encoding is a basic interface representing fixed-length (or known-length)
cryptographic objects or structures having a built-in binary encoding.
*/
type Encoding interface {

	// Encoded length of this object in bytes
	Len() int

	// Encode the content of this object into a slice,
	// whose length must be exactly Len().
	Encode() []byte

	// Decode the content of this object from a slice,
	// whose length must be exactly Len().
	Decode(buf []byte) error
}


// Not used other than for reflect.TypeOf()
var aSecret Secret
var aPoint Point

var tSecret = reflect.TypeOf(&aSecret).Elem()
var tPoint = reflect.TypeOf(&aPoint).Elem()


type decoder struct {
	g Group
	r io.Reader
}

func Read(r io.Reader, obj interface{}, g Group) error {
	de := decoder{g,r}
	return de.value(obj)
}

func (de *decoder) value(obj interface{}) error {

	// Does the object support our self-decoding interface?
	if e,ok := obj.(Encoding); ok {
		l := e.Len()
		b := make([]byte, l)
		if _,err := io.ReadFull(de.r, b); err != nil {
			return err
		}
		return e.Decode(b)
	}

	// Otherwise, reflectively handle composite types.
	switch v := reflect.ValueOf(obj); v.Kind() {

	case reflect.Interface:
		if v.IsNil() {
			// See if we can auto-fill certain interface variables
			t := v.Type()
			switch t {
			case tSecret:
				v.Set(reflect.ValueOf(de.g.Secret()).Addr())
			case tPoint:
				v.Set(reflect.ValueOf(de.g.Point()).Addr())
			default:
				panic("unsupported null pointer type: "+
					t.String())
			}
		}
		fallthrough
	case reflect.Ptr:
		return de.value(v.Elem().Interface())

	case reflect.Struct:
		l := v.NumField()
		for i := 0; i < l; i++ {
			if err := de.value(v.Field(i).Interface()); err != nil {
				return err
			}
		}

	case reflect.Array:
	case reflect.Slice:
		l := v.Len()
		for i := 0; i < l; i++ {
			if err := de.value(v.Index(i).Interface()); err != nil {
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
	return en.value(obj)
}

func (en *encoder) value(obj interface{}) error {

	// Does the object support our self-decoding interface?
	if e,ok := obj.(Encoding); ok {
		b := e.Encode()
		if _,err := en.w.Write(b); err != nil {
			return err
		}
		return nil
	}

	// Otherwise, reflectively handle composite types.
	switch v := reflect.ValueOf(obj); v.Kind() {

	case reflect.Interface:
	case reflect.Ptr:
		return en.value(v.Elem().Interface())

	case reflect.Struct:
		l := v.NumField()
		for i := 0; i < l; i++ {
			if err := en.value(v.Field(i).Interface()); err != nil {
				return err
			}
		}

	case reflect.Array:
	case reflect.Slice:
		l := v.Len()
		for i := 0; i < l; i++ {
			if err := en.value(v.Index(i).Interface()); err != nil {
				return err
			}
		}

	default:
		// Fall back to big-endian binary encoding
		return binary.Write(en.w, binary.BigEndian, obj)
	}
	return nil
}

