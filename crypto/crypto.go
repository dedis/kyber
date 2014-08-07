/*
Package crypto provides a powerful and flexible API containing
public-key and symmetric-key cryptographic primitives needed by
applications such as Dissent that need more sophisticated
public-key primitives than just straightforward signing and encryption.
All cryptographic primitives in this API are represented by abstract interfaces
designed to be independent of specific cryptographic algorithms,
to facilitate upgrading to new cryptographic algorithms
or switching to alternative algorithms for exprimentation purposes.

The public-key crypto API includes an abstract group interface
generically supporting a broad class of group-based public-key primitives
including DSA-style integer Schnorr groups and elliptic curve groups.
Users of this API can thus write higher-level crypto algorithms
such as zero-knowledge proofs without knowing or caring
exactly what kind of group,
let alone which precise security parameters or elliptic curves,
are being used.
The abstract group interface supports the standard algebraic
operations on group elements and secrets that nontrivial
public-key algorithms tend to rely on.
The interface uses additive group terminology typical for elliptic curves,
such that point addition is homomorphically equivalent to
adding their (potentially secret) scalar multipliers.
But the API and its operations apply equally well to DSA-style integer groups.

This package and its sub-packages also provide several specific
implementations of these abstract cryptographic interfaces.
The ciphersuites within this package build on the "native" Go
cryptographic libraries;
sub-packages build on other crypto libraries such as OpenSSL.
*/
package crypto

