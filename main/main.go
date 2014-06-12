package main

import "dissent/crypto"
import "dissent/crypto/openssl"

func main() {
	crypto.TestAES128SHA256QR2048()
	crypto.TestCurve()
	openssl.TestOpenSSL()
}

