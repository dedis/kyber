package protobuf

import (
	"fmt"
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
func Encode(structPtr interface{}) []byte {
	en := encoder{}
	en.message(reflect.ValueOf(structPtr).Elem())
	return en.Bytes()
}

func (en *encoder) message(sval reflect.Value) {

	// Encode all fields in-order
	nfield := sval.NumField()
	var idx [1]int
	for i := 0; i < nfield; i++ {
		idx[0] = i
		field := sval.FieldByIndex(idx[:])
		key := uint64(1+i) << 3
		//fmt.Printf("field %d: %s %v\n", 1+i,
		//		sval.Type().Field(i).Name, field.CanSet())
		if field.CanSet() {		// Skip blank/padding fields
			en.value(key, field)
		}
	}
}

func (en *encoder) value(key uint64, val reflect.Value) {

	// Handle pointer or interface values (possibly within slices)
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
	case reflect.Int32,reflect.Int64:
		en.uvarint(key | 0)
		en.svarint(val.Int())

	// Varint-encoded 32-bit and 64-bit unsigned integers.
	case reflect.Uint32,reflect.Uint64:
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

	// Embedded messages.
	case reflect.Struct:	// embedded message
		en.uvarint(key | 2)
		emb := encoder{}
		emb.message(val)
		b := emb.Bytes()
		en.uvarint(uint64(len(b)))
		en.Write(b)

	// Length-delimited slices or byte-vectors.
	case reflect.Slice:
		en.slice(key, val)
		return

	// Optional field: encode only if pointer is non-nil.
	case reflect.Ptr:
		if val.IsNil() {
			return
		}
		en.value(key, val.Elem())

	// Abstract interface field.
	case reflect.Interface:	
		if val.IsNil() {
			return
		}

		// If the object support self-encoding, use that.
		if enc,ok := val.Interface().(crypto.Encoding); ok {
			en.uvarint(key | 2)
			en.Write(enc.Encode())
			return
		}

		// Encode from the object the interface points to.
		en.value(key, val.Elem())

	default:
		panic(fmt.Sprintf("unsupported field Kind %d",val.Kind()))
	}
}

func (en *encoder) slice(key uint64, slval reflect.Value) {

	if slval.Kind() != reflect.Slice {
		panic("no slice passed")
	}
	sllen := slval.Len()
	packed := encoder{}
	switch slt := slval.Interface().(type) {
	case []bool:
		for i := 0; i < sllen; i++ {
			v := uint64(0)
			if slt[i] {
				v = 1
			}
			packed.uvarint(v)
		}

	case []int32:
		for i := 0; i < sllen; i++ {
			packed.svarint(int64(slt[i]))
		}

	case []int64:
		for i := 0; i < sllen; i++ {
			packed.svarint(slt[i])
		}

	case []uint32:
		for i := 0; i < sllen; i++ {
			packed.uvarint(uint64(slt[i]))
		}

	case []uint64:
		for i := 0; i < sllen; i++ {
			packed.uvarint(slt[i])
		}

	case []float32:
		for i := 0; i < sllen; i++ {
			packed.u32(math.Float32bits(slt[i]))
		}

	case []float64:
		for i := 0; i < sllen; i++ {
			packed.u64(math.Float64bits(slt[i]))
		}

	case []byte:	// Write the whole byte-slice as one key,value pair
		en.uvarint(key | 2)
		en.uvarint(uint64(sllen))
		en.Write(slt)
		return

	default:	// Write each element as a separate key,value pair
		for i := 0; i < sllen; i++ {
			en.value(key, slval.Index(i))
		}
		return
	}

	// Encode packed representation key/value pair
	en.uvarint(key | 2)
	b := packed.Bytes()
	en.uvarint(uint64(len(b)))
	en.Write(b)
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

