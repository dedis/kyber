package protobuf

import (
	"math"
	"bytes"
	"reflect"
	"encoding/binary"
	"dissent/crypto"
)


type encoder struct {
	bytes.Buffer
}

// Encode a Go struct into protocol buffer format.
// The caller must pass a pointer to the struct to encode.
func Encode(structPtr interface{}) ([]byte,error) {
	en := encoder{}
	if err := en.message(reflect.ValueOf(structPtr).Elem(), 0); err != nil {
		return nil,err
	}
	return en.Bytes(),nil
}

func (en *encoder) message(sval reflect.Value, depth int) error {

	// Encode all fields in-order
	nfield := sval.NumField()
	for i := 0; i < nfield; i++ {
		field := sval.FieldByIndex([]int{i})
		key := uint64(1+i) << 3

		// Handle slices and non-slices
		if field.Kind() == reflect.Slice &&
				field.Type().Elem().Kind() != reflect.Uint8 {
			slen := field.Len()
			for j := 0; j < slen; j++ {
				err := en.value(key, field.Index(j), depth)
				if err != nil {
					return err
				}
			}
		} else {
			// Non-slice field (or byte-slice)
			if err := en.value(key, field, depth); err != nil {
				return err
			}
		}
	}
	return nil
}

func (en *encoder) value(key uint64, val reflect.Value, depth int) error {

	// Handle pointer or interface values (possibly within slices)
	switch val.Kind() {
	case reflect.Ptr:
		// Optional field: encode only if pointer is non-nil.
		if val.IsNil() {
			return nil
		}
		val = val.Elem()

	case reflect.Interface:	
		// Abstract interface field.
		if val.IsNil() {
			return nil
		}

		// If the object support self-encoding, use that.
		if enc,ok := val.Interface().(crypto.Encoding); ok {
			en.uvarint(key | 2)
			_,err := en.Write(enc.Encode())
				return err
			return err
		}

		// Encode from the object the interface points to.
		val = val.Elem()
	}

	// Handle type-specific decoding
	switch val.Kind() {
	case reflect.Bool:
		en.uvarint(key | 0)
		v := uint64(0)
		if val.Bool() {
			v = 1
		}
		en.uvarint(v)

	// Varint-encoded 32-bit and 64-bit signed integers.
	// Note that protobufs don't support 8- or 16-bit ints.
	case reflect.Int32:
	case reflect.Int64:
		en.uvarint(key | 0)
		en.svarint(val.Int())

	// Varint-encoded 32-bit and 64-bit unsigned integers.
	case reflect.Uint32:
	case reflect.Uint64:
		en.uvarint(key | 0)
		en.uvarint(val.Uint())

	// Fixed-length 32-bit floats.
	case reflect.Float32:
		en.uvarint(key | 5)
		en.u32(math.Float32bits(float32(val.Float())))

	// Fixed-length 64-bit floats.
	case reflect.Float64:
		en.uvarint(key | 1)
		en.u64(math.Float64bits(val.Float()))

	// Length-delimited string.
	case reflect.String:
		en.uvarint(key | 2)
		b := []byte(val.String())
		en.uvarint(uint64(len(b)))
		en.Write(b)

	// Length-delimited byte-vectors.
	case reflect.Slice:
		en.uvarint(key | 2)
		b := val.Interface().([]byte)
		en.uvarint(uint64(len(b)))
		en.Write(b)

	// Embedded messages.
	case reflect.Struct:	// embedded message
		en.uvarint(key | 2)
		emb := encoder{}
		if err := emb.message(val, depth+1); err != nil {
			return err
		}
		b := emb.Bytes()
		en.uvarint(uint64(len(b)))
		en.Write(b)

	default:
		panic("unsupported field Kind")
	}
	return nil
}

func (en *encoder) uvarint(v uint64) {
	var b [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(b[:],v)
	en.Write(b[:n])
}

func (en *encoder) svarint(v int64) {
	if v >= 0 {
		en.uvarint(uint64(v) << 1)
	} else {
		en.uvarint(^uint64(v << 1))
	}
}

func (en *encoder) u32(v uint32) {
	var b [4]byte
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	en.Write(b[:])
}

func (en *encoder) u64(v uint64) {
	var b [8]byte
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
	en.Write(b[:])
}

