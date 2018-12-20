[![Docs](https://img.shields.io/badge/docs-current-brightgreen.svg)](https://godoc.org/github.com/dedis/kyber)
[![Build Status](https://travis-ci.org/dedis/kyber.svg?branch=master)](https://travis-ci.org/dedis/kyber)

DEDIS Advanced Crypto Library for Go
====================================

This package provides a toolbox of advanced cryptographic primitives for Go,
targeting applications like [Cothority](https://github.com/dedis/cothority)
that need more than straightforward signing and encryption.
Please see the
[Godoc documentation for this package](http://godoc.org/github.com/dedis/kyber)
for details on the library's purpose and API functionality.

This package includes a mix of variable time and constant time
implementations. If your application is sensitive to timing-based attacks
and you need to constrain Kyber to offering only constant time implementations,
you should use the [suites.RequireConstantTime()](https://godoc.org/github.com/dedis/kyber/suites#RequireConstantTime)
function in the `init()` function of your `main` package.

Versioning - Development
------------------------

We use the following versioning model:

* crypto.v0 was the previous semi-stable version. See
  [migration notes](https://github.com/dedis/kyber/wiki/Migration-from-gopkg.in-dedis-crypto.v0).
* kyber.v1 never existed, in order to keep kyber, onet and cothorithy versions linked
* kyber.v2 is the stable version
* the master branch of kyber is the development version

So if you depend on the master branch, you can expect breakages from time
to time. If you need something that doesn't change in a backward-compatible
way you should do:

```
   import "gopkg.in/dedis/kyber.v2"
```

Installing
----------

First make sure you have [Go](https://golang.org) version 1.8 or newer installed.

The basic crypto library requires only Go and a few
third-party Go-language dependencies that can be installed automatically
as follows:

	go get github.com/dedis/kyber
	cd "$(go env GOPATH)/src/github.com/dedis/kyber"
	go get -t ./... # install 3rd-party dependencies

You should then be able to test its basic function as follows:

	go test -v

You can recursively test all the packages in the library as follows:

	go test -v ./...

A note on deriving shared secrets
---------------------------------

Traditionally, ECDH (Elliptic curve Diffie-Hellman) derives the shared secret
from the x point only. In this framework, you can either manually retrieve the
value or use the MarshalBinary method to take the combined (x, y) value as the
shared secret. We recommend the latter process for new softare/protocols using
this framework as it is cleaner and generalizes across different types of
groups (e.g., both integer and elliptic curves), although it will likely be
incompatible with other implementations of ECDH. See [the Wikipedia page](http://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman) on ECDH.
