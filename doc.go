/*
Package crypto provides a toolbox of advanced cryptographic primitives,
for applications that need more than straightforward signing and encryption.
The cornerstone of this toolbox is the 'abstract' sub-package,
which defines abstract interfaces to cryptographic primitives
designed to be independent of specific cryptographic algorithms,
to facilitate upgrading applications to new cryptographic algorithms
or switching to alternative algorithms for experimentation purposes.

Abstract Groups and Crypto Suites

This toolkit's public-key crypto API includes an abstract.Group interface
generically supporting a broad class of group-based public-key primitives
including DSA-style integer residue groups and elliptic curve groups.
Users of this API can thus write higher-level crypto algorithms
such as zero-knowledge proofs without knowing or caring
exactly what kind of group,
let alone which precise security parameters or elliptic curves,
are being used.
The abstract group interface supports the standard algebraic
operations on group elements and scalars that nontrivial
public-key algorithms tend to rely on.
The interface uses additive group terminology typical for elliptic curves,
such that point addition is homomorphically equivalent to
adding their (potentially secret) scalar multipliers.
But the API and its operations apply equally well to DSA-style integer groups.

The abstract.Suite interface builds further on the abstract.Group API
to represent an abstraction of entire pluggable ciphersuites,
which include a group (e.g., curve) suitable for advanced public-key crypto
together with a suitably matched set of symmetric-key crypto algorithms.

As a trivial example, generating a public/private keypair is as simple as:

	a := suite.Scalar().Pick(random.Stream) // Alice's private key
	A := suite.Point().Mul(nil, a)          // Alice's public key

The first statement picks a private key (Scalar)
from a specified source of cryptographic random or pseudo-random bits,
while the second performs elliptic curve scalar multiplication
of the curve's standard base point (indicated by the 'nil' argument to Mul)
by the scalar private key 'a'.
Similarly, computing a Diffie-Hellman shared secret using
Alice's private key 'a' and Bob's public key 'B' can be done via:

	S := suite.Point().Mul(B, a)		// Shared Diffie-Hellman secret

Note that we use 'Mul' rather than 'Exp' here because the library
uses the additive-group terminology common for elliptic curve crypto,
rather than the multiplicative-group terminology of traditional integer groups -
but the two are semantically equivalent and
the interface itself works for both elliptic curve and integer groups.
See below for more complete examples.

Higher-level Building Blocks

Various sub-packages provide several specific
implementations of these abstract cryptographic interfaces.
In particular, the 'nist' sub-package provides implementations
of modular integer groups underlying conventional DSA-style algorithms,
and of NIST-standardized elliptic curves built on the Go crypto library.
The 'edwards' sub-package provides the abstract group interface
using more recent Edwards curves,
including the popular Ed25519 curve.
The 'openssl' sub-package offers an alternative implementation
of NIST-standardized elliptic curves and symmetric-key algorithms,
built as wrappers around OpenSSL's crypto library.

Other sub-packages build more interesting high-level cryptographic tools
atop these abstract primitive interfaces,
including:

- poly: Polynomial commitment and verifiable Shamir secret splitting
for implementing verifiable 't-of-n' threshold cryptographic schemes.
This can be used to encrypt a message so that any 2 out of 3 receivers
must work together to decrypt it, for example.

- proof: An implementation of the general Camenisch/Stadler framework
for discrete logarithm knowledge proofs.
This system supports both interactive and non-interactive proofs
of a wide variety of statements such as,
"I know the secret x associated with public key X
or I know the secret y associated with public key Y",
without revealing anything about either secret
or even which branch of the "or" clause is true.

- anon: Anonymous and pseudonymous public-key encryption and signing,
where the sender of a signed message or the receiver of an encrypted message
is defined as an explicit anonymity set containing several public keys
rather than just one.
For example, a member of an organization's board of trustees
might prove to be a member of the board without revealing which member she is.

- shuffle: Verifiable cryptographic shuffles of ElGamal ciphertexts,
which can be used to implement (for example) voting or auction schemes
that keep the sources of individual votes or bids private
without anyone having to trust the shuffler(s) to shuffle votes/bids honestly.

Disclaimer

For now this library should currently be considered experimental:
it will definitely be changing in non-backward-compatible ways,
and it will need independent security review
before it should be considered ready for use in security-critical applications.
However, we intend to bring the library
closer to stability and real-world usability
as quickly as development resources permit,
and as interest and application demand dictates.

As should be obvious,
this library is intended the use of developers who are
at least moderately knowledgeable about crypto.
If you want a crypto library that makes it easy
to implement "basic crypto" functionality correctly -
i.e., plain public-key encryption and signing -
then the NaCl/Sodium pursues this worthy goal (http://doc.libsodium.org).
This toolkit's purpose is to make it possible -
and preferably but not necessarily easy -
to do slightly more interesting things that most current crypto libraries
don't support effectively.
The one existing crypto library that this toolkit is probably most comparable to
is the Charm rapid prototyping library for Python (http://charm-crypto.com/).

This library incorporates and/or builds on existing code
from a variety of sources,
as documented in the relevant sub-packages.
*/
package crypto
