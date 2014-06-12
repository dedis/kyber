package main

import "dissent/crypto"
import "dissent/crypto/openssl"

func main() {
//	crypto.TestAES128SHA256QR2048()
//	crypto.TestCurve()
//	openssl.TestOpenSSL()

	println("\nNative suite:")
	crypto.BenchSuite(crypto.NewAES128SHA256P256())

	println("\nOpenSSL suite:")
	crypto.BenchSuite(openssl.NewOpenSSL())
}

