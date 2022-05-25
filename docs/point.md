## Introduction
A point represemts a element of public-key cryptographic group. 
For example,
A point can be a number modulo the prime P in a DSA-style Schnorr group,
or an (x, y) point on elliptic curve.
A point can contain a Diffie-Hellman public key, an Elgamal ciphertext, etc.

In here a point is implemented by the use of an interface by the name **Point**.

## Data Members
### Marshalling
Marshaling is a basic interface representing fixed-length (or known-length)
cryptographic objects or structures having a built-in binary encoding.
Implementors must ensure that calls to these methods do not modify
the underlying object so that other users of the object can access
it concurrently.

## Functions
### Equal()

|            |                           |
| ---------- | ------------------------- |
| Function   | `Point.Equal(Point) bool` |
| Parameters | `Point`                   |
| Output     | `Boolean`                 |

This function is used to check the equality of two Points derived from the same group. It return a `true/false` indicating wether the Points are equal or not.

### Null()

|            |                       |
| ---------- | --------------------- |
| Function   | `Point.Null() Point`  |
| Parameters | `None`                |
| Output     | `Point`               |

This function sets the receiver object to a neutral identity element, depending upon the suite taken into consideration. 

### Base()

|            |                       |
| ---------- | --------------------- |
| Function   | `Point.Base() Point`  |
| Parameters | `None`                |
| Output     | `Point`               |

This function sets the receiver object to the parent group's standard base.

### Pick()

|            |                                    |
| ---------- | ---------------------------------- |
| Function   | `Point.Pick(cipher.Stream) Point`  |
| Parameters | `cipher.Stream`                    |
| Output     | `Point`                            |

This functions sets the receiver object to a random or psuedo-random Point, which is extracted with the help of the cipher.Stream which is passed as a parameter to the function.

### Set()

|            |                           |
| ---------- | ------------------------- |
| Function   | `Point.Set(Point) Point`  |
| Parameters | `Point`                   |
| Output     | `Point`                   |

This function sets the receiver object's value to the Point specified by another object passed as a parameter to the function.

### Clone()

|            |                       |
| ---------- | --------------------- |
| Function   | `Point.Clone() Point` |
| Parameters | `None`                |
| Output     | `Point`               |

This functions clones the underlying object.

### Add()

|            |                                 |
| ---------- | ------------------------------- |
| Function   | `Point.Add(Point, Point) Point` |
| Parameters | `Point, Point`                  |
| Output     | `Point`                         |

This function sets the receiving object to the sum of two Points passed to the function as parameters. This addition is achieved such the scalars of those two Points add homomorphically.

### Sub()

|            |                                 |
| ---------- | ------------------------------- |
| Function   | `Point.Sub(Point, Point) Point` |
| Parameters | `Point, Point`                  |
| Output     | `Point`                         |

This function sets the receiving object to the difference of the two Points passed as parameters to the function. This substraction is achieved such that the scalars of those two Points are substracted homorphically.

### Neg()

|            |                          |
| ---------- | ------------------------ |
| Function   | `Point.Neg(Point) Point` |
| Parameters | `Point`                  |
| Output     | `Point`                  |

This function sets the receiving object to the negation of the Point passed to the function as the parameter.

### Mul()

|            |                                  |
| ---------- | -------------------------------- |
| Function   | `Point.Mul(Scalar, Point) Point` |
| Parameters | `Scalar, Point`                  |
| Output     | `Point`                          |

This function sets the receiving obejct to the product of the Point and the Scalar, passed to the function as parameters. If the Point is equal to the null value then the Scalar is multiplied with the standard base, which depends upon the suite being used.
