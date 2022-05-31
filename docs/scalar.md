## Introduction
Scalar represents a scalar value by which a Point (group element) may be encrypted to prduce another Point. This is an exponent in DSA-style groups, in which security is based on the Discrete Logarithm assumption, and a scalar multiplier in elliptic curve groups.

## Data Members
### Marshalling
Marshaling is a basic interface representing fixed-length (or known-length)
cryptographic objects or structures having a built-in binary encoding.
Implementors must ensure that calls to these methods do not modify
the underlying object so that other users of the object can access
it concurrently.

## Functions
### Equal()

|            |                             |
| ---------- | --------------------------- |
| Function   | `Scalar.Equal(Scalar) bool` |
| Parameters | `Scalar`                    |
| Output     | `Boolean`                   |

This function is used to check the equality of two Scalars derived from the same group. The functions return a `true/false` indicating wether the Points are equal or not.

### Set()

|            |                            |
| ---------- | -------------------------- |
| Function   | `Scalar.Set(Scalar) Scalar`|
| Parameters | `Scalar`                   |
| Output     | `Scalar`                   |

This function sets the receiver object's value to the Scalar specified by another object passed as a parameter to the function.

### Clone()

|            |                         |
| ---------- | ----------------------- |
| Function   | `Scalar.Clone() Scalar` |
| Parameters | `None`                  |
| Output     | `Scalar`                |

This function returns a new Scalar with the same value as the Scalar which called the function.

### SetInt64()

|            |                                |
| ---------- | ------------------------------ |
| Function   | `Scalar.SetInt64(int64) Scalar`|
| Parameters | `int64`                        |
| Output     | `Scalar`                       |

This function sets the value of the calling object to a small integer value, which is passed to the function as a parameter.

### Zero()

|            |                            |
| ---------- | -------------------------- |
| Function   | `Scalar.Zero() Scalar`     |
| Parameters | `None`                     |
| Output     | `Scalar`                   |

This function sets the value of the calling object equal to the additive identity.

### One()

|            |                            |
| ---------- | -------------------------- |
| Function   | `Scalar.One() Scalar`      |
| Parameters | `None`                     |
| Output     | `Scalar`                   |

This function sets the value of the calling object equal to the multiplicative identity.

### Add()

|            |                                          |
| ---------- | ---------------------------------------- |
| Function   | `Scalar.Add(Scalar, Scalar) Scalar`      |
| Parameters | `Scalar, Scalar`                         |
| Output     | `Scalar`                                 |

This function sets the receiving object to the modular sum of scalars passed to the function as parameters.

### Sub()

|            |                                          |
| ---------- | ---------------------------------------- |
| Function   | `Scalar.Sub(Scalar, Scalar) Scalar`      |
| Parameters | `Scalar, Scalar`                         |
| Output     | `Scalar`                                 |

This function sets the receiving object to the modular difference (Scalar 1 - Scalar 2) of the scalars passed as parameters.

### Neg()

|            |                                  |
| ---------- | -------------------------------- |
| Function   | `Scalar.Neg(Scalar) Scalar`      |
| Parameters | `Scalar`                         |
| Output     | `Scalar`                         |

This function sets the receiving object to the modular negation of the Scalar passed to the function as parameter.

### Mul()

|            |                                          |
| ---------- | ---------------------------------------- |
| Function   | `Scalar.Mul(Scalar, Scalar) Scalar`      |
| Parameters | `Scalar, Scalar`                         |
| Output     | `Scalar`                                 |

This function sets the receiving object to the modular product of the Scalars passed to the function as parameters.

### Div()

|            |                            |
| ---------- | -------------------------- |
| Function   | `Scalar.One() Scalar`      |
| Parameters | `None`                     |
| Output     | `Scalar`                   |

This function sets the receiving object to the modular division (Scalar 1 / Scalar 2) of the two Scalars passed to the function as parameters.

### Inv()

|            |                                  |
| ---------- | -------------------------------- |
| Function   | `Scalar.Inv(Scalar) Scalar`      |
| Parameters | `Scalar`                         |
| Output     | `Scalar`                         |

This function sets the receiving object to the modular inverse of the Scalar passed to the function as parameter.

### Pick()

|            |                                    |
| ---------- | ---------------------------------- |
| Function   | `Scalar.Pick(cipher.Stream) Scalar`|
| Parameters | `cipher.Stream`                    |
| Output     | `Scalar`                           |

This functions sets the receiver object to a random or psuedo-random Scalar, which is extracted with the help of the cipher.Stream which is passed as a parameter to the function.

### SetBytes()

|            |                                  |
| ---------- |----------------------------------|
| Function   | `Scalar.SetBytes([]byte) Scalar` |
| Parameters | `[]byte`                         |
| Output     | `Scalar`                         |

SetBytes sets the value of the scalar from a byte-slice, reducing if necessary to the appropriate modulus. The endianess of the byte-slice is determined by the implementation.

