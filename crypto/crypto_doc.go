// Package crypto offers some functions that are often used in our code.
//
// hash.go provides some utilities regarding the hashing of bytes, files or
// stream. The most common way to use it is to call:
// `HashStream(sha256.New(),stream)`. It will stream the input into the hash
// function by chunks and output the final hash.
//
// schnorr.go provides some crypto-shortcuts: Schnorr signature and a Hash-function.
// See https://en.wikipedia.org/wiki/Schnorr_signature
//
// It provides a way to sign a message using a private key and to verify the
// signature using the public counter part.
package crypto
