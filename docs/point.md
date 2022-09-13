## Introduction

A point represents a element of public-key cryptographic group. For example, A
point can be a number modulo the prime P in a DSA-style Schnorr group, or an (x,
y) point on elliptic curve. A point can contain a Diffie-Hellman public key, an
Elgamal ciphertext, etc.

In here a point is implemented by the use of an interface by the name **Point**.

```
type Point interface {
	Marshaling
	
	Equal(s2 Point) bool
	Null() Point
	Base() Point
	Pick(rand cipher.Stream) Point
	Set(p Point) Point
	Clone() Point
	EmbedLen() int
	Embed(data []byte, r cipher.Stream) Point
	Data() ([]byte, error)
	Add(a, b Point) Point
	Sub(a, b Point) Point
	Neg(a Point) Point
	Mul(s Scalar, p Point) Point
}
```

## Data Members

### [Marshaling](marshalling.md)

Marshaling is a basic interface representing fixed-length (or known-length)
cryptographic objects or structures having a built-in binary encoding.
Implementors must ensure that calls to these methods do not modify the
underlying object so that other users of the object can access it concurrently.

## Functions

### Equal()

|            |                                                                      |
| ---------- |----------------------------------------------------------------------|
| Function   | `Point.Equal(Point) bool`                                            |
| Parameters | - `Point` : The Point with which the equality has to be checked with |
| Output     | - `Boolean` : Answer to the equality of the points                   |

This function is used to check the equality of two Points derived from the same
group. It returns a `true/false` indicating wether the Points are equal or not.

### Null()

|            |                                                                           |
| ---------- |---------------------------------------------------------------------------|
| Function   | `Point.Null() Point`                                                      |
| Parameters | - `None`                                                                  |
| Output     | - `Point` : Caller Point with value equal to the neutral identity element |

This function sets the receiver object to a neutral identity element, depending
upon the suite taken into consideration. 

### Base()

|            |                                                                        |
| ---------- |------------------------------------------------------------------------|
| Function   | `Point.Base() Point`                                                   |
| Parameters | - `None`                                                               |
| Output     | - `Point` : Caller Point with value equal to the group's standard base |

This function sets the receiver object to the parent group's standard base.

### Pick()

|            |                                                                                |
| ---------- |--------------------------------------------------------------------------------|
| Function   | `Point.Pick(cipher.Stream) Point`                                              |
| Parameters | - `cipher.Stream` : Source from which random / pseudo-random values are picked |
| Output     | - `Point` : Caller Point with a random / pseudo-random value                   |

This functions sets the receiver object to a random or pseudo-random Point,
which is extracted with the help of the
[cipher.Stream](https://pkg.go.dev/crypto/cipher#Stream) which is passed as a
parameter to the function.

### Set()

|            |                                                                      |
| ---------- |----------------------------------------------------------------------|
| Function   | `Point.Set(Point) Point`                                             |
| Parameters | - `Point` : Point whose value has to be set to the current Point     |
| Output     | - `Point` : Caller Point with the same value as the parametric Point |

This function sets the receiver object's value to the Point specified by another
object passed as a parameter to the function.

### Clone()

|            |                                                               |
| ---------- |---------------------------------------------------------------|
| Function   | `Point.Clone() Point`                                         |
| Parameters | - `None`                                                      |
| Output     | - `Point` : A new point which is a clone of the caller object |

This functions clones the underlying object.

### Add()

|            |                                                                              |
| ---------- |------------------------------------------------------------------------------|
| Function   | `Point.Add(Point, Point) Point`                                              |
| Parameters | - `Point, Point` : The two points which have to be added                     |
| Output     | - `Point` : Caller Point with value equal to the sum of the above two Points |

This function sets the receiving object to the sum of two Points passed to the
function as parameters. This addition is achieved such the scalars of those two
Points add homomorphically.

### Sub()

|            |                                                                                     |
| ---------- |-------------------------------------------------------------------------------------|
| Function   | `Point.Sub(Point, Point) Point`                                                     |
| Parameters | - `Point, Point` : The two Points which have to subtracted                          |
| Output     | - `Point` : Caller Point with value equal to the difference of the above two Points |

This function sets the receiving object to the difference of the two Points
passed as parameters to the function. This substraction is achieved such that
the scalars of those two Points are substracted homorphically.

### Neg()

|            |                                                                                                |
| ---------- |------------------------------------------------------------------------------------------------|
| Function   | `Point.Neg(Point) Point`                                                                       |
| Parameters | - `Point` : Point whose value has to be negated                                                |
| Output     | - `Point` : Caller Point with value equal to the negation of the value of the parametric Point |

This function sets the receiving object to the negation of the Point passed to
the function as the parameter.

### Mul()

|            |                                                                                             |
| ---------- |---------------------------------------------------------------------------------------------|
| Function   | `Point.Mul(Scalar, Point) Point`                                                            |
| Parameters | - `Scalar, Point` : The Scalar and the Point which have to the multiplied                   |
| Output     | - `Point` : Caller Point with value equal to the product of the parametric Scalar and Point |

This function sets the receiving object to the product of the Point and the
Scalar, passed to the function as parameters. If the Point is equal to the null
value then the Scalar is multiplied with the standard base, which depends upon
the suite being used.

### EmbedLen()

|            |                                                                                   |
| ---------- |-----------------------------------------------------------------------------------|
| Function   | `Point.EmbedLen() int`                                                            |
| Parameters | - `None`                                                                          |
| Output     | - `int` : Maximum number of bytes which can be embedded in a single group element |

The EmbedLen function returns the maximum number of bytes that can be embedded
in a single group element via the Pick() function.

### Embeded()

|            |                                                                                                                                            |
| ---------- |--------------------------------------------------------------------------------------------------------------------------------------------|
| Function   | `Point.Embed(data []byte, r cipher.Stream) Point`                                                                                          |
| Parameters | - `[]byte` : Byte encoding of the message to be embedded <br/>- `cipher.Stream` - Source from where random values for the Point are picked |
| Output     | - `Point` : Caller Point with a random new value and the given message embedded to it                                                      |

Embed encodes a limited amount of specified data in the Point, using r as a
source of cryptographically secure random data.  Implementations only embed the
first EmbedLen bytes of the given data.

### Data()

|            |                                                                                                                                                             |
| ---------- |-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Function   | `Point.Data() ([]byte, error)`                                                                                                                              |
| Parameters | - `None`                                                                                                                                                    |
| Output     | - `[]byte` : Byte encoding of the embedded message in the caller Point<br/>- `error` : Contains an error if something unexpected happened, otherwise is nil |

This function extracts the data embedded in a Point chosen via Embed(). It
returns an error if the Point doesn't represent valid embedded data.
