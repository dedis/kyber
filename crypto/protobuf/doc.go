// Package protobuf implements Protocol Buffers reflectively
// using Go types to define message formats.
// This approach provides convenience similar to Gob encoding,
// but with a language-neutral wire format.
// For general information on Protocol buffers see
// http://protobuf.googlecode.com.
//
// In contrast with the goprotobuf and gogoprotobuf packages for Go,
// users of this implementation need not write or compile .proto files;
// you just define the message formats you want as Go struct types.
// Of course if you want code in other languages to interoperate
// using the same message formats you may end up needing to write
// .proto files for the code in those other languages,
// but the translation between a Go struct definition
// and a basic Protocol Buffers message format definition is straightforward.
//
// XXX explain struct interpretation: required, optional, repeated...
// Interface elements are considered abstract objects,
// to be bound to concrete object types at runtime.
// Those concrete object types can be further structs for reprotobuf to parse,
// or can support the Encoding interface to define their own binary encoding.
//
// XXX a downside is that dynamic reflection is generally less efficient
// than use of statically generated code, as gogoprotobuf does for example.
// If we decide we want the convenience of format definitions in Go
// with the runtime performance of code generation,
// we could in principle achieve that by adding a "Go-format"
// message format compiler frontend to goprotobuf or gogoprotobuf.
//
// Some current limitations:
//
// - No support (yet) for packed repeated fields.
//   One way to add this would be to recognize a field name suffix,
//   e.g., "_packed", as indicating the field should use packed encoding.
//
// - No graceful support (yet) for message format with sparse field numbers.
//   This might be handled with another kind of field name suffix,
//   e.g., "_75" to set the field number counter to 75 starting this field.
// 
// - No support (yet) for [s]fixed{32,64}.
//
// - When decoding we currently don't actually check whether all "required"
//   message fields actually appeared in the byte-stream;
//   any that didn't will just be left with the zero value for that field.
//   We could add checking for this, but it would slow down decoding more.
//
package protobuf
