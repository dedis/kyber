DeDiS Advanced Crypto Library for Go
====================================

This package provides a toolbox of advanced cryptographic primitives for Go,
targeting applications like [Dissent](http://dedis.cs.yale.edu/dissent/)
that need more than straightforward signing and encryption.
Please see the
[GoDoc documentation for this package](http://godoc.org/github.com/DeDiS/crypto)
for details on the library's purpose and functionality.

Installing
----------

First make sure you have [Go](https://golang.org)
version 1.3 or newer installed.

Install C library dependencies.

Pairing-Based Cryptographay: [PBC](http://crypto.stanford.edu/pbc/)
    
    Mac (with homebrew):   $ brew install pbc
    Otherwise: Install from source.
        
    Download from source [http://crypto.stanford.edu/pbc/download.html](http://crypto.stanford.edu/pbc/download.html)
    Unzip the source directory
    cd into the source directory
    $ ./configure
    $ make
    $ make install

Now you can install the crypto library:

	go get github.com/dedis/crypto
    cd $GOPATH/src/github.com/dedis/crypto
    go get ./... # install 3rd-party dependencies

It is ok if you get the error:

    # github.com/dedis/crypto/sodium/ed25519
    sodium/ed25519/curve.go:310: cannot use suite (type \*suite) as type
    abstract.Suite in return argument:
        *suite does not implement abstract.Suite (missing Sponge method)

You should then be able to test its basic function as follows:

	cd $GOPATH/src/github.com/dedis/crypto
	go test -v

You can recursively test all the packages in the library as follows,
keeping in mind that some sub-packages will only build
if certain dependencies are satisfied as described below:

	go test -v ./...

Dependencies
------------

The library's basic functionality depends only on the Go standard library.
However, parts of the library will only build if certain other,
optional system packages are installed with their header files and libraries
(e.g., the "-dev" version of the package).
In particular:

- crypto.openssl: This sub-package is a wrapper that builds on
the [OpenSSL](https://www.openssl.org/) crypto library
to provide a fast, mature implementation
of NIST-standardized elliptic curves and symmetric cryptosystems.

- crypto.pbc: This is a wrapper for the
[Stanford Pairing-Based Crypto (PBC) library](http://crypto.stanford.edu/pbc/),
which will of course only work if the PBC library is installed.

Copyright (C) 2014 Yale DeDiS Group
-----------------------------------

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA  02110-1301, USA.
