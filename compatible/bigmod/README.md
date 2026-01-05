This package is a copy of the original bigmod package `filippo.io/bigmod` used in go. 
Below is the original README from the original package.

Package bigmod implements constant-time big integer arithmetic modulo large
moduli. Unlike math/big, this package is suitable for implementing
security-sensitive cryptographic operations. It is a re-exported version the
standard library package crypto/internal/fips140/bigmod used to implement
crypto/rsa amongst others.

v0.1.0 is up to date with Go 1.24.

The API is NOT stable.
