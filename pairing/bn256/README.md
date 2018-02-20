bn256
-----

Package bn256 implements a particular bilinear group at the 128-bit security
level. It is a modification of the official version at
https://golang.org/x/crypto/bn256 but all operations are ~10 times faster. There
is a `lattices` branch for non-commercial use where non-pairing operations are
up to ~20 times faster.

Bilinear groups are the basis of many of the new cryptographic protocols that
have been proposed over the past decade. They consist of a triplet of groups
(G₁, G₂ and GT) such that there exists a function e(g₁ˣ,g₂ʸ)=gTˣʸ (where gₓ is a
generator of the respective group). That function is called a pairing function.

This package specifically implements the Optimal Ate pairing over a 256-bit
Barreto-Naehrig curve as described in
http://cryptojedi.org/papers/dclxvi-20100714.pdf. Its output is compatible with
the implementation described in that paper.

### Benchmarks

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
