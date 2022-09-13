## Introduction

An XOF is an extendable output function, which is a cryptographic primitive that
can take arbitrary input in the same way a hash function does, and then create a
stream of output, up to a limit determined by the size of the internal state of
the hash function the underlies the XOF.

When XORKeyStream is called with zeros for the source, an XOF also acts as a
PRNG. If it is seeded with an appropriate amount of keying material, it is a
cryptographically secure source of random bits.

```
type XOF interface {
	io.Writer
	io.Reader
	cipher.Stream

	Reseed()
	Clone() XOF
}
```

## Members

### Writer

The XOF interface consists of an [io.Writer](https://pkg.go.dev/io#Writer). The
`Write` function of Writer absorbs more data into the hash's state. It panics if
called after `Read` function of the [io.Reader](https://pkg.go.dev/io#Reader)
interface. Use `Reseed()` to reset the XOF into a state where more data can be
absorbed via `Write`.

### Reader

The `Read` function of the [io.Reader](https://pkg.go.dev/io#Reader) interface
reads more output from the hash. It returns [io.EOF](https://pkg.go.dev/io#EOF)
if the limit of available data for reading has been reached. 

### Stream

An XOF implements [cipher.Stream](https://pkg.go.dev/crypto/cipher#Stream), so
that callers can use XORKeyStream to encrypt/decrypt data. The key stream is
read from the XOF using the [io.Reader](https://pkg.go.dev/io#Reader) interface.
If Read returns an error, then XORKeyStream will panic.

## Functions

### Reseed()

The Reseed function makes the caller XOF writeable again after it has been read
from by sampling a key from it's output and initializing a fresh XOF
implementation with that key.

|            |                |
| ---------- |----------------|
| Function   | `XOF.Reseed()` |
| Parameters | - `None`       |
| Output     | - `None`       |

### Clone()
Clone returns a copy of the caller XOF in its current state.

|            |                                                        |
| ---------- |--------------------------------------------------------|
| Function   | `XOF.Clone() XOF`                                      |
| Parameters | - `None`                                               |
| Output     | - `XOF` : A new XOF which is a clone of the caller XOF |