// This package implements a simple "rigid" binary encoding
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
package marshal

import (
	"encoding"
	"fmt"
	"io"
	//"reflect"
	"golang.org/x/net/context"
	"strings"
)

type Marshaler interface {
	// Encode the contents of this object and write it to an io.Writer.
	Marshal(c context.Context, w io.Writer) (int, error)
}

type Unmarshaler interface {
	// Decode the content of this object by reading from an io.Reader.
	// If r is a Cipher, uses it to pick a valid object pseudo-randomly,
	// which may entail reading more than Len bytes due to retries.
	Unmarshal(c context.Context, r io.Reader) (int, error)
}

// Marshaling is an extension of the BinaryMarshaler/BinaryUnmarshaler
// interfaces that adds methods to marshal directly to/from I/O streams.
// These stream-based methods are often simpler to implement and/or use,
// and either can generally be implemented readily in terms of the other.
//
// XXX maybe Marshaling interface not needed, just Marshaler/Unmarshaler?
type Marshaling interface {

	// XXX This may go away from the interface.
	String() string

	Marshaler
	Unmarshaler

	// Byte-slice binary marshaling interface
	encoding.BinaryMarshaler

	// Byte-slice binary unmarshaling interface
	encoding.BinaryUnmarshaler
}

// RigidMarshaling is a binary marshaling interface for objects
// whose size is fixed or depends only on
// well-known configuration information,
// and does not depend in any way on the content of the object(s) marshaled.
// Using a rigid encoding when feasible can simplify marshaling/unmarshaling,
// reduce risks of side-channel leakage via encoded object length,
// and generally make cryptographic objects of the same type more anonymous.
//
type RigidMarshaling interface {
	Marshaling

	// Encoded length of this object in bytes.
	MarshalSize() int
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
//
// XXX this should probably be replaced by proper use of Context.
/*
type Constructor interface {
	New(t reflect.Type) interface{}
}
*/

func prindent(depth int, format string, a ...interface{}) {
	fmt.Print(strings.Repeat("  ", depth))
	fmt.Printf(format, a...)
}
