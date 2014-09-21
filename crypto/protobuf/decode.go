package protobuf

import (
	"math"
	"errors"
	"reflect"
	"encoding/binary"
	"dissent/crypto"
)


// A NewMap is a map defining how to instantiate interface types
// encountered while reading and decoding structured data.
// The keys are reflect.Type values denoting interface types.
// The corresponding values are functions expected to instantiate,
// and initialize as necessary,
// some appropriate concrete object type supporting that interface.
//
// The Dissent crypto library uses this capability in particular
// to support dynamic instantiation of Point and Secret objects
// of the concrete type appropriate for a given crypto.Suite.
//
type NewMap map[reflect.Type]func()interface{}


type decoder struct {
	nm map[reflect.Type]func()interface{}
}

// Decode a protocol buffer into a Go struct.
// The caller must pass a pointer to the struct to decode into and,
// optionally, a constructor map with which to instantiate interface types.
func Decode(buf []byte, structPtr interface{}, newmap NewMap) error {
	de := decoder{map[reflect.Type]func()interface{}(newmap)}
	return de.message(buf, reflect.ValueOf(structPtr).Elem(), 0)
}

// Decode a Protocol Buffers message into a Go struct.
// The Kind of the passed value v must be Struct.
func (de *decoder) message(buf []byte, sval reflect.Value, depth int) error {

	// Decode all the fields 
	nfields := sval.NumField()
	for len(buf) > 0 {
		// Parse the key
		key,n := binary.Uvarint(buf)
		if n <= 0 {
			return errors.New("bad protobuf field key")
		}
		buf = buf[n:]
		wiretype := key & 7
		fieldnum := key >> 3

		// Break out the value based on the wire type
		var v uint64
		var vb []byte
		switch wiretype {
		case 0:		// varint
			v,n = binary.Uvarint(buf)
			if n <= 0 {
				return errors.New("bad protobuf varint value")
			}
			buf = buf[n:]

		case 5:		// 32-bit
			if len(buf) < 4 {
				return errors.New("bad protobuf 64-bit value")
			}
			v =	uint64(buf[0]) |
				uint64(buf[1])<<8 |
				uint64(buf[2])<<16 |
				uint64(buf[3])<<24
			buf = buf[4:]

		case 1:		// 64-bit
			if len(buf) < 8 {
				return errors.New("bad protobuf 64-bit value")
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
				return errors.New(
					"bad protobuf length-delimited value")
			}
			vb = buf[n:n+int(v)]
			buf = buf[n+int(v):]

		default:
			return errors.New("unknown protobuf wire-type")
		}

		// Lookup the corresponding struct field
		if fieldnum <= 0 || fieldnum > uint64(nfields) {
			// Unrecognized message field; just skip it
			continue
		}
		field := sval.FieldByIndex([]int{int(fieldnum-1)})

		// Set up to handle slices representing repeated fields,
		// except for byte-slices, which are atomic in protobufs.
		slice := false
		val := field
		if field.Kind() == reflect.Slice &&
				field.Type().Elem().Kind() != reflect.Uint8 {
			// Create a temporary Value to decode this field into,
			// then we'll append it to the slice after decoding.
			val = de.instantiate(field.Type().Elem())
			slice = true
		}

		// Handle pointer or interface values (possibly within slices)
		switch val.Kind() {
		case reflect.Ptr:
			// Optional field: instantiate pointer's element type.
			if val.IsNil() {
				val.Set(de.instantiate(val.Type().Elem()))
			}
			val = val.Elem()

		case reflect.Interface:	
			// Abstract field: instantiate via dynamic constructor.
			if val.IsNil() {
				val.Set(de.instantiate(val.Type()))
			}

			// If the object support self-decoding, use that.
			enc,ok := val.Interface().(crypto.Encoding)
			if ok {
				if wiretype != 2 {
					return errors.New(
						"bad wiretype for bytes")
				}
				if err := enc.Decode(vb); err != nil {
					return err
				}
				if slice {
					reflect.Append(field, val)
				}
				continue
			}

			// Decode into the object the interface points to.
			// XXX perhaps better ONLY to support self-decoding
			// for interface fields?
			val = val.Elem()
		}

		// Handle type-specific decoding
		switch val.Kind() {
		case reflect.Bool:
			if wiretype != 0 {
				return errors.New("bad wiretype for bool")
			}
			val.SetBool(v != 0)

		// Varint-encoded 32-bit and 64-bit signed integers.
		// Note that protobufs don't support 8- or 16-bit ints.
		case reflect.Int32:
		case reflect.Int64:
			if wiretype != 0 {
				return errors.New("bad wiretype for sint")
			}
			sv := int64(v) >> 1
			if v & 1 != 0 {
				sv = ^sv
			}
			val.SetInt(int64(sv))

		// Varint-encoded 32-bit and 64-bit unsigned integers.
		case reflect.Uint32:
		case reflect.Uint64:
			if wiretype != 0 {
				return errors.New("bad wiretype for uint")
			}
			val.SetUint(uint64(v))

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

		// Length-delimited byte-vectors.
		case reflect.Uint8:
			if !slice {
				panic("protobuf supports only byte-slices")
			}
			if wiretype != 2 {
				return errors.New("bad wiretype for bytes")
			}
			reflect.AppendSlice(field, reflect.ValueOf(vb))
			slice = false	// we've handled it

		case reflect.Struct:	// embedded message
			if wiretype != 2 {
				return errors.New(
					"bad wiretype for embedded message")
			}
			if err := de.message(vb, val, depth+1); err != nil {
				return err
			}

		default:
			panic("unsupported field Kind "+val.Kind().String())
		}

		// If the field was a slice, append the value to it.
		if slice {
			reflect.Append(field, val)
		}
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


