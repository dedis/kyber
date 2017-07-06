package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v2/log"
)

func TestConnType(t *testing.T) {
	var tests = []struct {
		Value    string
		Expected ConnType
	}{
		{"tcp", PlainTCP},
		{"tls", TLS},
		{"purb", PURB},
		{"tcp4", InvalidConnType},
		{"_tls", InvalidConnType},
	}

	for _, str := range tests {
		if connType(str.Value) != str.Expected {
			t.Error("Wrong ConnType for " + str.Value)
		}
	}
}

func TestAddress(t *testing.T) {
	var tests = []struct {
		Value   string
		Valid   bool
		Type    ConnType
		Address string
		Host    string
		Port    string
		Public  bool
	}{
		{"tls://10.0.0.4:2000", true, TLS, "10.0.0.4:2000", "10.0.0.4", "2000", false},
		{"tcp://10.0.0.4:2000", true, PlainTCP, "10.0.0.4:2000", "10.0.0.4", "2000", false},
		{"tcp://67.43.129.85:2000", true, PlainTCP, "67.43.129.85:2000", "67.43.129.85", "2000", true},
		{"purb://10.0.0.4:2000", true, PURB, "10.0.0.4:2000", "10.0.0.4", "2000", false},
		{"tls://[::]:1000", true, TLS, "[::]:1000", "[::]", "1000", false},
		{"tls4://10.0.0.4:2000", false, InvalidConnType, "", "", "", false},
		{"tls://1000.0.0.4:2000", false, InvalidConnType, "", "", "", false},
		{"tls://10.0.0.4:20000000", false, InvalidConnType, "", "", "", false},
		{"tls://10.0.0.4:-10", false, InvalidConnType, "", "", "", false},
		{"tlsx10.0.0.4:2000", false, InvalidConnType, "", "", "", false},
		{"tls:10.0.0.4x2000", false, InvalidConnType, "", "", "", false},
		{"tlsx10.0.0.4x2000", false, InvalidConnType, "", "", "", false},
		{"tlxblurdie", false, InvalidConnType, "", "", "", false},
		{"tls://blublublu", false, InvalidConnType, "", "", "", false},
	}

	for i, str := range tests {
		log.Lvl1("Testing", str)
		add := Address(str.Value)
		assert.Equal(t, str.Valid, add.Valid(), "Address (%d) %s", i, str.Value)
		assert.Equal(t, str.Type, add.ConnType(), "Address (%d) %s", i, str.Value)
		assert.Equal(t, str.Address, add.NetworkAddress())
		assert.Equal(t, str.Host, add.Host())
		assert.Equal(t, str.Port, add.Port())
		assert.Equal(t, str.Public, add.Public())
	}
}
