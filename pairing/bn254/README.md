## bn254

Package bn254 implements a particular bilinear group.

Note: this _is_ the curve implemented in Ethereum.

Bilinear groups are the basis of many of the new cryptographic protocols that
have been proposed over the past decade. They consist of a triplet of groups
(G₁, G₂ and GT) such that there exists a function e(g₁ˣ,g₂ʸ)=gTˣʸ (where gₓ is a
generator of the respective group). That function is called a pairing function.

This package specifically implements the Optimal Ate pairing over a 256-bit
Barreto-Naehrig curve as described in
http://cryptojedi.org/papers/dclxvi-20100714.pdf. Its output is compatible with
the implementation described in that paper.

This package previously claimed to operate at a 128-bit security level. However,
recent improvements in attacks mean that is no longer true. See
https://moderncrypto.org/mail-archive/curves/2016/000740.html.

## Kyber additions

The basis for this package is [Cloudflare's bn256 implementation](https://github.com/cloudflare/bn256)
which itself is an improved version of the [official bn256 package](https://golang.org/x/crypto/bn256).
The package at hand maintains compatibility to Cloudflare's library. The biggest difference is the replacement of their
[public API](https://github.com/cloudflare/bn256/blob/master/bn256.go) by a new
one that is compatible to Kyber's scalar, point, group, and suite interfaces.
