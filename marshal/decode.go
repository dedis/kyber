package marshal

import (
	"encoding/binary"
	"errors"
	"io"
	"reflect"
)

type decoder struct {
	c Constructor
	r io.Reader
}

// Read a series of binary objects from an io.Reader.
// The objs must be a list of pointers.
func (e BinaryEncoding) Read(r io.Reader, objs ...interface{}) error {
	de := decoder{e.Constructor, r}
	for i := 0; i < len(objs); i++ {
		// XXX check that it's a by-reference type
		// (pointer, slice, etc.) and complain if not,
		// to head of accidental misuse?
		if err := de.value(reflect.ValueOf(objs[i]), 0); err != nil {
			return err
		}
	}
	return nil
}

func (de *decoder) value(v reflect.Value, depth int) error {

	// Does the object support our self-decoding interface?
	obj := v.Interface()
	if e, ok := obj.(Marshaling); ok {
		_, err := e.UnmarshalFrom(de.r)
		//prindent(depth, "decode: %s\n", e.String())
		return err
	}
	var err error
	// Otherwise, reflectively handle composite types.
	//prindent(depth, "%s: %s\n", v.Kind().String(), v.Type().String())
	switch v.Kind() {

	case reflect.Interface:
		if v.IsNil() {
			// See if we can auto-fill certain interface variables
			t := v.Type()
			o := de.c.New(t)
			if o == nil {
				panic("unsupported null pointer type: " +
					t.String())
			}
			v.Set(reflect.ValueOf(o))
		}
		fallthrough
	case reflect.Ptr:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		return de.value(v.Elem(), depth+1)

	case reflect.Struct:
		l := v.NumField()
		for i := 0; i < l; i++ {
			if err = de.value(v.Field(i), depth+1); err != nil {
				return err
			}
		}

	case reflect.Slice:
		if v.IsNil() {
			panic("slices must be initialized to correct length before decoding")
		}
		fallthrough
	case reflect.Array:
		l := v.Len()
		for i := 0; i < l; i++ {
			if err = de.value(v.Index(i), depth+1); err != nil {
				return err
			}
		}

	case reflect.Int:
		var i int64
		err := binary.Read(de.r, binary.BigEndian, &i)
		if int64(int(i)) != i {
			return errors.New("int too large for this platform")
		}
		v.SetInt(i)
		return err

	case reflect.Bool:
		var b uint8
		err := binary.Read(de.r, binary.BigEndian, &b)
		v.SetBool(b != 0)
		return err

	default:

		return binary.Read(de.r, binary.BigEndian, v.Addr().Interface())
	}
	return err
}
