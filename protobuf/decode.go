package protobuf

import (
	"math"
	"errors"
	"reflect"
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
)


// Constructors represents a map defining how to instantiate any interface types
// that Decode() might encounter while reading and decoding structured data.
// The keys are reflect.Type values denoting interface types.
// The corresponding values are functions expected to instantiate,
// and initialize as necessary,
// an appropriate concrete object type supporting that interface.
//
// The Dissent crypto library uses this capability, for example,
// to support dynamic instantiation of Point and Secret objects
// of the concrete type appropriate for a given abstract.Suite.
//
type Constructors map[reflect.Type]func()interface{}


type decoder struct {
	nm map[reflect.Type]func()interface{}
}

// Decode a protocol buffer into a Go struct.
// The caller must pass a pointer to the struct to decode into and,
// optionally, a map of constructors with which to instantiate interface types.
//
// Decode() currently does not explicitly check that all 'required' fields
// are actually present in the input buffer being decoded.
// If required fields are missing, then the corresponding fields
// will be left unmodified, meaning they will take on
// their default Go zero values if Decode() is passed a fresh struct.
func Decode(buf []byte, structPtr interface{}, cons Constructors) error {
	de := decoder{map[reflect.Type]func()interface{}(cons)}
	return de.message(buf, reflect.ValueOf(structPtr).Elem())
}

// Decode a Protocol Buffers message into a Go struct.
// The Kind of the passed value v must be Struct.
func (de *decoder) message(buf []byte, sval reflect.Value) error {

	// Decode all the fields 
	nfields := sval.NumField()
	for len(buf) > 0 {
		// Parse the key
		key,n := binary.Uvarint(buf)
		if n <= 0 {
			return errors.New("bad protobuf field key")
		}
		buf = buf[n:]
		wiretype := int(key & 7)
		fieldnum := key >> 3

		// Lookup the corresponding struct field.
		// Leave field with a zero Value if fieldnum is out-of-range.
		// In this case, as well as for blank fields,
		// value() will just skip over and discard the field content.
		var field reflect.Value
		if fieldnum > 0 && fieldnum <= uint64(nfields) {
			field = sval.FieldByIndex([]int{int(fieldnum-1)})
		}

		// Decode the field's value
		rem,err := de.value(wiretype, buf, field)
		if err != nil {
			return err
		}
		buf = rem
	}
	return nil
}

// Pull a value from the buffer and put it into a reflective Value.
func (de *decoder) value(wiretype int, buf []byte,
			val reflect.Value) ([]byte,error) {

	// Break out the value from the buffer based on the wire type
	var v uint64
	var n int
	var vb []byte
	switch wiretype {
	case 0:		// varint
		v,n = binary.Uvarint(buf)
		if n <= 0 {
			return nil,errors.New("bad protobuf varint value")
		}
		buf = buf[n:]

	case 5:		// 32-bit
		if len(buf) < 4 {
			return nil,errors.New("bad protobuf 64-bit value")
		}
		v =	uint64(buf[0]) |
			uint64(buf[1])<<8 |
			uint64(buf[2])<<16 |
			uint64(buf[3])<<24
		buf = buf[4:]

	case 1:		// 64-bit
		if len(buf) < 8 {
			return nil,errors.New("bad protobuf 64-bit value")
		}
		v =	uint64(buf[0]) |
			uint64(buf[1])<<8 |
			uint64(buf[2])<<16 |
			uint64(buf[3])<<24 |
			uint64(buf[4])<<32 |
			uint64(buf[5])<<40 |
			uint64(buf[6])<<48 |
			uint64(buf[7])<<56
		buf = buf[8:]

	case 2:		// length-delimited
		v,n = binary.Uvarint(buf)
		if n <= 0 || v > uint64(len(buf)-n) {
			return nil,errors.New(
				"bad protobuf length-delimited value")
		}
		vb = buf[n:n+int(v)]
		buf = buf[n+int(v):]

	default:
		return nil,errors.New("unknown protobuf wire-type")
	}

	// We've gotten the value out of the buffer,
	// now put it into the appropriate reflective Value.
	if err := de.putvalue(wiretype, val, v, vb); err != nil {
		return nil,err
	}

	return buf,nil
}

func (de *decoder) putvalue(wiretype int, val reflect.Value,
				v uint64, vb []byte) error {

	// If val is not settable, it either represents an out-of-range field
	// or an in-range but blank (padding) field in the struct.
	// In this case, simply ignore and discard the field's content.
	if !val.CanSet() {
		return nil
	}

	switch val.Kind() {
	case reflect.Bool:
		if wiretype != 0 {
			return errors.New("bad wiretype for bool")
		}
		if v > 1 {
			return errors.New("invalid bool value")
		}
		val.SetBool(v != 0)

	// Signed integers may be encoded either zigzag-varint or fixed
	// Note that protobufs don't support 8- or 16-bit ints.
	case reflect.Int,reflect.Int32,reflect.Int64:
		if wiretype == 0 {		// encoded as varint
			sv := int64(v) >> 1
			if v & 1 != 0 {
				sv = ^sv
			}
			val.SetInt(sv)
		} else if wiretype == 5 { // sfixed32
			val.SetInt(int64(int32(v)))
		} else if wiretype == 1 { // sfixed64
			val.SetInt(int64(v))
		} else {
			return errors.New("bad wiretype for sint")
		}

	// Varint-encoded 32-bit and 64-bit unsigned integers.
	case reflect.Uint32,reflect.Uint64:
		if wiretype == 0 {
			val.SetUint(v)
		} else if wiretype == 5 { // ufixed32
			val.SetUint(uint64(uint32(v)))
		} else if wiretype == 1 { // ufixed64
			val.SetUint(uint64(v))
		} else {
			return errors.New("bad wiretype for uint")
		}

	// Fixed-length 32-bit floats.
	case reflect.Float32:
		if wiretype != 5 {
			return errors.New("bad wiretype for float32")
		}
		val.SetFloat(float64(math.Float32frombits(uint32(v))))

	// Fixed-length 64-bit floats.
	case reflect.Float64:
		if wiretype != 1 {
			return errors.New("bad wiretype for float64")
		}
		val.SetFloat(math.Float64frombits(v))

	// Length-delimited string.
	case reflect.String:
		if wiretype != 2 {
			return errors.New("bad wiretype for string")
		}
		val.SetString(string(vb))

	// Embedded message
	case reflect.Struct:
		if wiretype != 2 {
			return errors.New("bad wiretype for embedded message")
		}
		return de.message(vb, val)

	// Optional field
	case reflect.Ptr:
		// Instantiate pointer's element type.
		if val.IsNil() {
			val.Set(de.instantiate(val.Type().Elem()))
		}
		return de.putvalue(wiretype, val.Elem(), v, vb)

	// Repeated field or byte-slice
	case reflect.Slice:
		if wiretype != 2 {
			return errors.New("bad wiretype for repeated field")
		}
		return de.slice(val, vb)

	case reflect.Interface:	
		// Abstract field: instantiate via dynamic constructor.
		if val.IsNil() {
			val.Set(de.instantiate(val.Type()))
		}

		// If the object support self-decoding, use that.
		enc,ok := val.Interface().(abstract.Encoding)
		if ok {
			if wiretype != 2 {
				return errors.New(
					"bad wiretype for bytes")
			}
			return enc.Decode(vb)
		}

		// Decode into the object the interface points to.
		// XXX perhaps better ONLY to support self-decoding
		// for interface fields?
		return de.putvalue(wiretype, val.Elem(), v, vb)

	default:
		panic("unsupported value kind "+val.Kind().String())
	}
	return nil
}

// Instantiate an arbitrary type, handling dynamic interface types.
// Returns a Ptr value.
func (de *decoder) instantiate(t reflect.Type) reflect.Value {

	// If it's an interface type, lookup a dynamic constructor for it.
	if t.Kind() == reflect.Interface {
		newfunc,ok := de.nm[t]
		if !ok {
			panic("no constructor for interface "+t.String())
		}
		return reflect.ValueOf(newfunc())
	}

	// Otherwise, for all concrete types, just instantiate directly.
	return reflect.New(t)
}

var sfixed32type = reflect.TypeOf(Sfixed32(0))
var sfixed64type = reflect.TypeOf(Sfixed64(0))
var ufixed32type = reflect.TypeOf(Ufixed32(0))
var ufixed64type = reflect.TypeOf(Ufixed64(0))

// Handle decoding of slices
func (de *decoder) slice(slval reflect.Value, vb []byte) error {

	// Find the element type, and create a temporary instance of it.
	eltype := slval.Type().Elem()
	val := reflect.New(eltype).Elem()

	// Decide on the wiretype to use for decoding.
	var wiretype int
	switch eltype.Kind() {
	case reflect.Bool,reflect.Int32,reflect.Int64,
			reflect.Uint32,reflect.Uint64:
		switch eltype {
		case sfixed32type:
			wiretype = 5	// Packed 32-bit representation
		case sfixed64type:
			wiretype = 1	// Packed 64-bit representation
		case ufixed32type:
			wiretype = 5	// Packed 32-bit representation
		case ufixed64type:
			wiretype = 1	// Packed 64-bit representation
		default:
			wiretype = 0	// Packed varint representation
		}

	case reflect.Float32:
		wiretype = 5		// Packed 32-bit representation

	case reflect.Float64:
		wiretype = 1		// Packed 64-bit representation

	case reflect.Uint8:		// Unpacked byte-slice
		slval.SetBytes(vb)
		return nil

	default:			// Other unpacked repeated types
		// Just unpack and append one value from vb.
		if err := de.putvalue(2, val, 0, vb); err != nil {
			return err
		}
		slval.Set(reflect.Append(slval, val))
		return nil
	}

	// Decode packed values from the buffer and append them to the slice.
	for len(vb) > 0 {
		rem,err := de.value(wiretype, vb, val)
		if err != nil {
			return err
		}
		slval.Set(reflect.Append(slval, val))
		vb = rem
	}
	return nil
}

