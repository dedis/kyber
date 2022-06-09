## Introduction

The Suite interface is the sum total all suite mix-ins provided in kyber. For
example - `SuiteEd255219`, the suite for the edwards 25519 curve
```
type Suite interface {
	kyber.Encoding
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}
```

## Members

### Encoding

Encoding represents an abstract interface to an encoding/decoding that can be
used to marshal/unmarshal objects to and from streams. Different Encodings will
have different constraints, of course. Two implementations are available:

1. The protobuf encoding using the variable length Google Protobuf encoding
   scheme. The library is available at
   [https://go.dedis.ch/protobuf](https://go.dedis.ch/protobuf) 
2. The fixbuf encoding, a fixed length binary encoding of arbitrary structures.
   The library is available at
   [https://go.dedis.ch/fixbuf](https://go.dedis.ch/fixbuf)

The structure of the Encoding interface is as follows:
```
type Encoding interface {
	Write(w io.Writer, objs ...interface{}) error
	Read(r io.Reader, objs ...interface{}) error
}
```

#### Functions

* The `Write()` function encodes and writes objects to an
  [io.Writer](https://pkg.go.dev/io#Writer)

    |            |                                                                                                                                                  |
    |------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
    | Function   | `Suite.Write(io.Writer, ...interface{}) error`                                                                                                   |
    | Parameters | - `io.Writer` : The destination writer to which the object will be marshalled <br/>- `...interface{}` : Group of objects that have to be encoded |
    | Output     | - `error` : Contains an error if something unexpected happened, otherwise is nil                                                                 |

* The `Read()` function read and decodes objects from an
  [io.Reader](https://pkg.go.dev/io#Reader)

    |            |                                                                                                                                       |
    | ---------- |---------------------------------------------------------------------------------------------------------------------------------------|
    | Function   | `Suite.Read(io.Reader, ...interface{}) error`                                                                                         |
    | Parameters | - `io.Reader` : The source reader from which the objects are read <br/>- `...interface{}` : Group of objects which have to be decoded |
    | Output     | - `error` : Contains an error if something unexpected happened, otherwise is nil                                                      |


### [Group](group.md)

Group interface represents a mathematical group usable for Diffie-Hellman key
exchange, ElGamal encryption, and the related body of public-key cryptographic
algorithms and zero-knowledge proof methods. The Group interface is designed in
particular to be a generic front-end to both traditional DSA-style modular
arithmetic groups and ECDSA-style elliptic curves the caller of this interface's
methods need not know or care which specific mathematical construction underlies
the interface.

### Hash Factory

The HashFactory interface provides the user with the hash function being used in
the caller suite.

```
type HashFactory interface {
	Hash() hash.Hash
}
```

It consists of a single function `Hash()` which returns a new object of the hash
function being used. For example -  It returns a new instance of the SHA256 hash
in the case of the ED25519 curve. It returns a value of the type
[hash.Hash](https://pkg.go.dev/hash#Hash)

|            |                                                                          |
| ---------- |--------------------------------------------------------------------------|
| Function   | `Suite.Hash() hash.Hash`                                                 |
| Parameters | - `None`                                                                 |
| Output     | - `hash.Hash` : New instance of a hash corresponding to the caller suite |

### XOF Factory

The XOFFactory interface is used to create and returns a new [XOF](xof.md). 
```
type XOFFactory interface {
	XOF(seed []byte) XOF
}
```
It consists of a single function `XOF(seed []byte)` which creates a new XOF,
feeding seed to it via it's `Write` method. If seed is nil or `[]byte{}`, the
XOF is left unseeded, it will produce a fixed, predictable stream of bits.

(Caution: this behavior is useful for testing but fatal for production use).

|            |                                                                       |
| ---------- |-----------------------------------------------------------------------|
| Function   | `Suite.XOF([]byte) XOF`                                               |
| Parameters | - `None`                                                              |
| Output     | - `XOF` : A new instance of the XOF corresponding to the caller suite |

### Random

The Random interface is used to produce a cryptographically random key stream. 
```
type Random interface {
	RandomStream() cipher.Stream
}
```
It consists of a single function `RandomStream()` which returns a
[cipher.Stream](https://pkg.go.dev/crypto/cipher#Stream) that produces a
cryptographically random key stream. The stream can tolerate being used in
multiple goroutines.

|            |                                                                                   |
| ---------- |-----------------------------------------------------------------------------------|
| Function   | `Suite.RandomStream() cipher.Stream`                                              |
| Parameters | - `None`                                                                          |
| Output     | - `cipher.Stream` : Source from which random / pseudo-random values can be chosen |