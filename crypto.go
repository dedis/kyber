/*
Package crypto provides a toolbox of advanced cryptographic primitives,
for applications that need more than straightforward signing and encryption.
The cornerstone of this toolbox is the 'abstract' sub-package,
which defines abstract interfaces to cryptographic primitives
designed to be independent of specific cryptographic algorithms,
to facilitate upgrading applications to new cryptographic algorithms
or switching to alternative algorithms for exprimentation purposes.

This toolkit's public-key crypto API includes an abstract.Group interface
generically supporting a broad class of group-based public-key primitives
including DSA-style integer residue groups and elliptic curve groups.
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

The abstract.Suite interface builds further on the abstract.Group API
to represent an abstraction of entire pluggable ciphersuites,
which include a group (e.g., curve) suitable for advanced public-key crypto
together with a suitably matched set of symmetric-key crypto algorithms.

Various sub-packages provide several specific
implementations of these abstract cryptographic interfaces.
In particular, the 'nist' sub-package provides implementations
of modular integer groups underlying conventional DSA-style algorithms,
and of NIST-standardized elliptic curves built on the Go crypto library.
The 'edwards' sub-package provides the abstract group interface
using more recent Edwards curves, including the popular Ed25519 curve.
The 'openssl' sub-package offers an alternative implementation
of NIST-standardized elliptic curves and symmetric-key algorithms,
built as wrappers around OpenSSL's crypto library.
*/
package crypto

