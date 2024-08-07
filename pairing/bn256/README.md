bn256
-----

Package bn256 implements a particular bilinear group.

Bilinear groups are the basis of many of the new cryptographic protocols that
have been proposed over the past decade. They consist of a triplet of groups
(G₁, G₂ and GT) such that there exists a function e(g₁ˣ,g₂ʸ)=gTˣʸ (where gₓ is a
generator of the respective group). That function is called a pairing function.

This package specifically implements the Optimal Ate pairing over a 256-bit
Barreto-Naehrig curve as described in
http://cryptojedi.org/papers/dclxvi-20100714.pdf. Its output is compatible with
the implementation described in that paper.

### Security Warnings
---
This package previously claimed to operate at a 128-bit security level. However,
recent improvements in attacks mean that is no longer true. See
https://moderncrypto.org/mail-archive/curves/2016/000740.html. 
We strongly recommend using the `BLS12-381` curve that still provide ~128-bit security and is not vulnerable to these improved attacks.

#### Modulo bias in Hash()
A modulo bias was found in [hashToPoint()](https://github.com/dedis/kyber/blob/9ac80102d756a21f318685e230e33791c44b5e2e/pairing/bn256/point.go#L239), for reason of backward compatibility we did not fix it. This problem was raised in issue [#439](https://github.com/dedis/kyber/issues/439). If backward compatibility is not a problem, and this is really the curve you want to use, a potential workaround is also suggested in the linked issue. Otherwise `BLS12-381` also provides `Hash()` as defined in [RFC9380](https://datatracker.ietf.org/doc/rfc9380/).

### Benchmarks
---

branch `master`:
```
BenchmarkG1-4        	   10000	    154995 ns/op
BenchmarkG2-4        	    3000	    541503 ns/op
BenchmarkGT-4        	    1000	   1267811 ns/op
BenchmarkPairing-4   	    1000	   1630584 ns/op
```

branch `lattices`:
```
BenchmarkG1-4        	   20000	     92198 ns/op
BenchmarkG2-4        	    5000	    340622 ns/op
BenchmarkGT-4        	    2000	    635061 ns/op
BenchmarkPairing-4   	    1000	   1629943 ns/op
```

official version:
```
BenchmarkG1-4        	    1000	   2268491 ns/op
BenchmarkG2-4        	     300	   7227637 ns/op
BenchmarkGT-4        	     100	  15121359 ns/op
BenchmarkPairing-4   	      50	  20296164 ns/op
```

Kyber additions
---------------

The basis for this package is [Cloudflare's bn256 implementation](https://github.com/cloudflare/bn256)
which itself is an improved version of the [official bn256 package](https://golang.org/x/crypto/bn256).
The package at hand maintains compatibility to Cloudflare's library. The biggest difference is the replacement of their
[public API](https://github.com/cloudflare/bn256/blob/master/bn256.go) by a new
one that is compatible to Kyber's scalar, point, group, and suite interfaces. *Last update 05.2024*
