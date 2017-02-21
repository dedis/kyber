# Changelog

Most important changes that _might_ break something.

## 170201 - Depend on stable crypto
 
As crypto will undergo work, we put all dependencies on `gopkg.in/dedis/crypto.v0`.
In your project, a simple

`find . -name "*go" | xargs perl -pi -e "s:github.com/dedis/crypto:gopkg.in/dedis/crypto.v0:`

will clean up things.