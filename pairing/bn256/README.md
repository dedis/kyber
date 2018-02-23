bn256
-----

Package bn256 implements a particular bilinear group at the 128-bit
security level. The basis for this package is the code from
https://github.com/cloudflare/bn256 which itself is a modification It is a
modification of the official version at https://golang.org/x/crypto/bn256 but
all operations are ~10 times faster.

Bilinear groups are the basis of many of the new cryptographic protocols that
have been proposed over the past decade. They consist of a triplet of groups
(G₁, G₂ and GT) such that there exists a function e(g₁ˣ,g₂ʸ)=gTˣʸ (where gₓ is a
generator of the respective group). That function is called a pairing function.

This package specifically implements the Optimal Ate pairing over a 256-bit
Barreto-Naehrig curve as described in
http://cryptojedi.org/papers/dclxvi-20100714.pdf. Its output is compatible with
the implementation described in that paper.
