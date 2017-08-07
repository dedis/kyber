package network

import (
	"testing"

	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/assert"
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

var staticHostIPMapping = make(map[string]string)

func dummyResolver(s string) ([]string, error) {
	return []string{staticHostIPMapping[s]}, nil
}

func TestAddress(t *testing.T) {
	lookupHost = dummyResolver
	staticHostIPMapping["google.com"] = "8.8.8.8"
	staticHostIPMapping["facebook.com"] = "20.20.20.20"
	staticHostIPMapping["epfl.ch"] = "100.100.100.100"
	staticHostIPMapping["localhost"] = "127.0.0.1"
	var tests = []struct {
		Value           string
		Valid           bool
		Type            ConnType
		Address         string
		Host            string
		Port            string
		Public          bool
		ResolvedHost    string
		ResolvedAddress string
	}{
		{"tls://10.0.0.4:2000", true, TLS, "10.0.0.4:2000", "10.0.0.4", "2000", false, "10.0.0.4", "10.0.0.4:2000"},
		{"tcp://10.0.0.4:2000", true, PlainTCP, "10.0.0.4:2000", "10.0.0.4", "2000", false, "10.0.0.4", "10.0.0.4:2000"},
		{"tcp://67.43.129.85:2000", true, PlainTCP, "67.43.129.85:2000", "67.43.129.85", "2000", true, "67.43.129.85", "67.43.129.85:2000"},
		{"purb://10.0.0.4:2000", true, PURB, "10.0.0.4:2000", "10.0.0.4", "2000", false, "10.0.0.4", "10.0.0.4:2000"},
		{"tls://[::]:1000", true, TLS, "[::]:1000", "[::]", "1000", false, "::", "[::]:1000"},
		{"tls4://10.0.0.4:2000", false, InvalidConnType, "", "", "", false, "", ""},
		{"tls://1000.0.0.4:2000", false, InvalidConnType, "", "", "", false, "", ""},
		{"tls://10.0.0.4:20000000", false, InvalidConnType, "", "", "", false, "", ""},
		{"tls://10.0.0.4:-10", false, InvalidConnType, "", "", "", false, "", ""},
		{"tlsx10.0.0.4:2000", false, InvalidConnType, "", "", "", false, "", ""},
		{"tls:10.0.0.4x2000", false, InvalidConnType, "", "", "", false, "", ""},
		{"tlsx10.0.0.4x2000", false, InvalidConnType, "", "", "", false, "", ""},
		{"tlxblurdie", false, InvalidConnType, "", "", "", false, "", ""},
		{"tls://blublublu", false, InvalidConnType, "", "", "", false, "", ""},
		// dummy values for the IP addresses, defined by dummyResolver
		{"tcp://localhost:80", true, PlainTCP, "localhost:80", "localhost", "80", false, "127.0.0.1", "127.0.0.1:80"},
		{"tcp://facebook.com:8080", true, PlainTCP, "facebook.com:8080", "facebook.com", "8080", true, "20.20.20.20", "20.20.20.20:8080"},
		{"tls://google.com:80", true, TLS, "google.com:80", "google.com", "80", true, "8.8.8.8", "8.8.8.8:80"},
		{"tcp://epfl.ch:8080", true, PlainTCP, "epfl.ch:8080", "epfl.ch", "8080", true, "100.100.100.100", "100.100.100.100:8080"},
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
		assert.Equal(t, str.ResolvedHost, add.Resolve())
		assert.Equal(t, str.ResolvedAddress, add.NetworkAddressResolved())
	}
}

// Isolated test case for validHostname
func TestDNSNames(t *testing.T) {
	assert.True(t, validHostname("myhost.secondlabel.org"))
	assert.True(t, validHostname("www.asd.lol.xd"))
	assert.True(t, validHostname("a.a"))
	assert.True(t, validHostname("localhost"))
	assert.True(t, validHostname("www.asd.lol.xd"))
	assert.True(t, validHostname("randomtext"))
	assert.False(t, validHostname("www.asd.lol.x-d"))
	assert.False(t, validHostname("192.168.1.1"))
	assert.False(t, validHostname("..a"))
	assert.False(t, validHostname("a..a"))
	assert.False(t, validHostname("123213.213"))
	assert.False(t, validHostname("-23.dwe"))
	assert.False(t, validHostname("..."))
	assert.False(t, validHostname("www.asd.lol.xd-"))
}
