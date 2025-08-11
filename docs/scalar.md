## Introduction

Scalar represents a scalar value by which a Point (group element) may be
encrypted to produce another Point. This is an exponent in DSA-style groups, in
which security is based on the Discrete Logarithm assumption, and a scalar
multiplier in elliptic curve groups.
```
type Scalar interface {
	Marshaling
	
	Equal(s2 Scalar) bool
	Set(a Scalar) Scalar
	Clone() Scalar
	SetInt64(v int64) Scalar
	Zero() Scalar
	Add(a, b Scalar) Scalar
	Sub(a, b Scalar) Scalar
	Neg(a Scalar) Scalar
	One() Scalar
	Mul(a, b Scalar) Scalar
	Div(a, b Scalar) Scalar
	Inv(a Scalar) Scalar
	Pick(rand cipher.Stream) Scalar
	SetBytes([]byte) Scalar
}
```

## Data Members

### Marshalling

Marshaling is a basic interface representing fixed-length (or known-length)
cryptographic objects or structures having a built-in binary encoding.
Implementors must ensure that calls to these methods do not modify the
underlying object so that other users of the object can access it concurrently.

## Functions

### Equal()

|            |                                                                        |
| ---------- |------------------------------------------------------------------------|
| Function   | `Scalar.Equal(Scalar) bool`                                            |
| Parameters | - `Scalar` : The Scalar with which the equality has to be checked with |
| Output     | - `Boolean` : Answer to the equality of the points                     |

This function is used to check the equality of two Scalars derived from the same
group. The functions return a `true/false` indicating wether the Points are
equal or not.

### Set()

|            |                                                                     |
| ---------- |---------------------------------------------------------------------|
| Function   | `Scalar.Set(Scalar) Scalar`                                         |
| Parameters | - `Scalar` : Scalar whose value has to be set to the current Scalar |
| Output     | - `Scalar` : Caller Scalar with same value as the parametric Scalar |

This function sets the receiver object's value to the Scalar specified by
another object passed as a parameter to the function.

### Clone()

|            |                                                                 |
| ---------- |-----------------------------------------------------------------|
| Function   | `Scalar.Clone() Scalar`                                         |
| Parameters | - `None`                                                        |
| Output     | - `Scalar` : A new Scalar which is a clone of the caller Scalar |

This function returns a new Scalar with the same value as the Scalar which
called the function.

### SetInt64()

|            |                                                             |
| ---------- |-------------------------------------------------------------|
| Function   | `Scalar.SetInt64(int64) Scalar`                             |
| Parameters | - `int64` : Value which is to be assigned to the Scalar     |
| Output     | - `Scalar` : Caller Scalar with value equal to the paramter |

This function sets the value of the calling object to a small integer value,
which is passed to the function as a parameter.

### Zero()

|            |                                                                             |
| ---------- |-----------------------------------------------------------------------------|
| Function   | `Scalar.Zero() Scalar`                                                      |
| Parameters | - `None`                                                                    |
| Output     | - `Scalar` : Caller Scalar with value equal to the group's addtive identity |

This function sets the value of the calling object equal to the additive
identity.

### One()

|            |                                                                                    |
| ---------- |------------------------------------------------------------------------------------|
| Function   | `Scalar.One() Scalar`                                                              |
| Parameters | - `None`                                                                           |
| Output     | - `Scalar` : Caller Scalar with value equal to the group's multiplicative identity |

This function sets the value of the calling object equal to the multiplicative
identity.

### Add()

|            |                                                                                              |
| ---------- |----------------------------------------------------------------------------------------------|
| Function   | `Scalar.Add(Scalar, Scalar) Scalar`                                                          |
| Parameters | - `Scalar, Scalar` : The two Scalars which have to be added                                  |
| Output     | - `Scalar` : Caller Scalar with value equal to the sum of the parametric Scalars |

This function sets the receiving object to the modular sum of scalars passed to
the function as parameters.

### Sub()

|            |                                                                                         |
| ---------- |-----------------------------------------------------------------------------------------|
| Function   | `Scalar.Sub(Scalar, Scalar) Scalar`                                                     |
| Parameters | - `Scalar, Scalar` : The two Scalars which have to be substracted                       |
| Output     | - `Scalar` : Caller Scalar with value equal to the difference of the parametric Scalars |

This function sets the receiving object to the modular difference (Scalar 1 -
Scalar 2) of the scalars passed as parameters.

### Neg()

|            |                                                                                              |
| ---------- |----------------------------------------------------------------------------------------------|
| Function   | `Scalar.Neg(Scalar) Scalar`                                                                  |
| Parameters | - `Scalar` : The Scalar whose value has to be negated                                        |
| Output     | - `Scalar` : Caller Scalar with value equal to the neagtion of the value of the given Scalar |

This function sets the receiving object to the modular negation of the Scalar
passed to the function as parameter.

### Mul()

|            |                                                                                       |
| ---------- |---------------------------------------------------------------------------------------|
| Function   | `Scalar.Mul(Scalar, Scalar) Scalar`                                                   |
| Parameters | - `Scalar, Scalar` : The two Scalars which have to be multiplied                      |
| Output     | - `Scalar` : Caller Scalar with value equal to the product of the paramtetric Scalars |

This function sets the receiving object to the modular product of the Scalars
passed to the function as parameters.

### Div()

|            |                                                                    |
| ---------- |--------------------------------------------------------------------|
| Function   | `Scalar.Div(Scalar, Scalar) Scalar`                                |
| Parameters | - `Scalar, Scalar` : Two Scalars which have to be divided          |
| Output     | - `Scalar` : Caller Scalar with value equal to Scalar 1 / Scalar 2 |

This function sets the receiving object to the modular division (Scalar 1 /
Scalar 2) of the two Scalars passed to the function as parameters.

### Inv()

|            |                                                                                 |
| ---------- |---------------------------------------------------------------------------------|
| Function   | `Scalar.Inv(Scalar) Scalar`                                                     |
| Parameters | - `Scalar` : The Scalar whose value has to be inverted                          |
| Output     | - `Scalar` : Caller Scalar with value equal to the inverse of parametric Scalar |

This function sets the receiving object to the modular inverse of the Scalar
passed to the function as parameter.

### Pick()

|            |                                                                                  |
| ---------- |----------------------------------------------------------------------------------|
| Function   | `Scalar.Pick(cipher.Stream) Scalar`                                              |
| Parameters | - `cipher.Stream` : Source from random / pseudo-random values are picked         |
| Output     | - `Scalar` : Caller Scalar with value equal to some random / pseudo-random value |

This functions sets the receiver object to a random or pseudo-random Scalar,
which is extracted with the help of the cipher.Stream which is passed as a
parameter to the function.

### SetBytes()

|            |                                                                                |
| ---------- |--------------------------------------------------------------------------------|
| Function   | `Scalar.SetBytes([]byte) Scalar`                                               |
| Parameters | - `[]byte` : Byte encoding of the value to be assigned in little endian format |
| Output     | - `Scalar` : Caller scalar with value corresponding to the given byte encoding |

SetBytes sets the value of the scalar from a byte-slice, reducing if necessary
to the appropriate modulus. The endianess of the byte-slice is determined by the
implementation. For example - In the case of the ED25519 curve the endianess is
Little Endianess.
