This package is a copy of the original bigmod package `filippo.io/bigmod` used in go. 
This package has been copied in order to be modified for our usage. We make
a few method for comparing natural numbers public as well as the `choice` struct (which 
is often used as return type to these comparisons). 
The file `pub_nat.go` contains all these changes.<br>
Below is the README from the original package.

Package bigmod implements constant-time big integer arithmetic modulo large
moduli. Unlike math/big, this package is suitable for implementing
security-sensitive cryptographic operations. It is a re-exported version the
standard library package crypto/internal/fips140/bigmod used to implement
crypto/rsa amongst others.

v0.1.0 is up to date with Go 1.24.

The API is NOT stable.
