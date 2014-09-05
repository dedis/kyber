package crypto

import (
	"testing"
)

func TestSchnorr(t *testing.T) {
	TestGroup(NewAES128SHA256QR512())
}

func TestP256(t *testing.T) {
	TestGroup(NewAES128SHA256P256())
}

