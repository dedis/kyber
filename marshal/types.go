package marshal

import (
	"encoding"
	"fmt"
	"io"
	"reflect"
	"strings"
)

/*
Marshaling is a basic interface representing fixed-length (or known-length)
cryptographic objects or structures having a built-in binary encoding.
*/
type Marshaling interface {

	// XXX This may go away from the interface.
	String() string

	// Encoded length of this object in bytes.
	MarshalSize() int

	// Encode the contents of this object and write it to an io.Writer.
	MarshalTo(w io.Writer) (int, error)

	// Decode the content of this object by reading from an io.Reader.
	// If r is a Cipher, uses it to pick a valid object pseudo-randomly,
	// which may entail reading more than Len bytes due to retries.
	UnmarshalFrom(r io.Reader) (int, error)

	// Byte-slice binary marshaling interface
	encoding.BinaryMarshaler

	// Byte-slice binary unmarshaling interface
	encoding.BinaryUnmarshaler
}

// Encoding represents an abstract interface to an encoding/decoding
// that can be used to marshal/unmarshal objects to and from streams.
// Different Encodings will have different constraints, of course.
//
// XXX not sure if this is an effective/useful interface,
// because different encodings (e.g., rigid vs protobufs)
// disagree even on whether they can take multiple arguments.
type Encoding interface {

	// Encode and write objects to an io.Writer.
	Write(w io.Writer, objs ...interface{}) error

	// Read and decode objects from an io.Reader.
	Read(r io.Reader, objs ...interface{}) error
}

// Constructor represents a generic constructor
// that takes a reflect.Type, typically for an interface type,
// and constructs some suitable concrete instance of that type.
// The crypto library uses this capability to support
// dynamic instantiation of cryptographic objects of the concrete type
// appropriate for a given abstract.Suite.
type Constructor interface {
	New(t reflect.Type) interface{}
}

// BinaryEncoding represents a simple binary encoding
// suitable for reading and writing fixed-length cryptographic objects.
// The interface allows reading and writing composite types
// such as structs, arrays, and slices,
// but the encoded size of any object must be completely defined
// by the type and size of the object itself and the ciphersuite in use.
//
// Slices must be instantiated to the correct length
// before either reading or writing:
// hence the reader must determine the correct length "out of band"
// (the encoding supports no transmission of length metadata).
//
// XXX move this and Constructor to some other, more generic package
//
type BinaryEncoding struct {
	Constructor // Constructor for instantiating abstract types

	// prevent clients from depending on the exact set of fields,
	// to reserve the right to extend in backward-compatible ways.
	hidden struct{}
}

func prindent(depth int, format string, a ...interface{}) {
	fmt.Print(strings.Repeat("  ", depth))
	fmt.Printf(format, a...)
}
