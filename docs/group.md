## Introduction

Group interface represents a mathematical group usable for Diffie-Hellman key
exchange, ElGamal encryption, and the related body of public-key cryptographic
algorithms and zero-knowledge proof methods. The Group interface is designed in
particular to be a generic front-end to both traditional DSA-style modular
arithmetic groups and ECDSA-style elliptic curves the caller of this interface's
methods need not know or care which specific mathematical construction underlies
the interface.

The Group interface is essentially just a "constructor" interface enabling the
caller to generate the two particular types of objects relevant to DSA-style
public-key cryptography; we call these objects Points and Scalars. The caller
must explicitly initialize or set a new Point or Scalar object to some value
before using it as an input to some other operation involving Point and/or
Scalar objects. For example, to compare a point P against the neutral (identity)
element, you might use P.Equal(suite.Point().Null()), but not just
P.Equal(suite.Point()).

It is expected that any implementation of this interface should satisfy suitable
hardness assumptions for the applicable group: e.g., that it is
cryptographically hard for an adversary to take an encrypted Point and the known
generator it was based on, and derive the Scalar with which the Point was
encrypted. Any implementation is also expected to satisfy the standard
homomorphism properties that Diffie-Hellman and the associated body of
public-key cryptography are based on.

```
type Group interface {
	String() string

	ScalarLen() int // Max length of scalars in bytes
	Scalar() Scalar // Create new scalar

	PointLen() int // Max length of point in bytes
	Point() Point  // Create new point
}
```

## Functions

### String()

|            |                                |
| ---------- |--------------------------------|
| Function   | `Suite.String() string`        |
| Parameters | - `None`                       |
| Output     | - `string` : Name of the suite |

This function returns the name of the suite, with which the function has been
called.

### ScalarLen()

|            |                                                       |
| ---------- |-------------------------------------------------------|
| Function   | `Suite.ScalarLen() int`                               |
| Parameters | - `None`                                              |
| Output     | - `int` : Maximum size in bytes of the encoded Scalar |

This function returns the maximum size in bytes of the encoded Scalar of the
caller suite   

### Scalar()

|            |                                                      |
| ---------- |------------------------------------------------------|
| Function   | `Suite.Scalar() Scalar`                              |
| Parameters | - `None`                                             |
| Output     | - `Scalar` : New Scalar instance of the caller suite |

This function creates and returns a new [Kyber Scalar](scalar.md) of the caller
suite.

### PointLen()

|            |                                                      |
| ---------- |------------------------------------------------------|
| Function   | `Suite.Point() int`                                  |
| Parameters | - `None`                                             |
| Output     | - `int` : Maximum size in bytes of the encoded Point |

This function returns the maximum length in bytes of an encoded Point of the
caller suite.

### Point()

|            |                                                    |
| ---------- |----------------------------------------------------|
| Function   | `Suite.Point() Point`                              |
| Parameters | - `None`                                           |
| Output     | - `Point` : New Point instance of the caller suite |

This function creates and returns a new [Kyber Point](point.md) of the caller
suite.

