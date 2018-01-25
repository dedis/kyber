package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

var o bytes.Buffer

func TestMain(m *testing.M) {
	out = &o
	log.MainTest(m)
}

var serverGroup string = `Description = "Default Dedis Cothority"

[[servers]]
  Address = "tcp://5.135.161.91:2000"
  Public = "94b8255379e11df5167b8a7ae3b85f7e7eb5f13894abee85bd31b3270f1e4c65"
  Description = "Nikkolasg's server: spreading the love of singing"

[[servers]]
  Address = "tcp://185.26.156.40:61117"
  Suite = "Ed25519"
  Public = "6a921638a4ade8970ebcd9e371570f08d71a24987f90f12391b9f6c525be5be4"
  Description = "Ismail's server"`

func TestReadGroupDescToml(t *testing.T) {
	group, err := ReadGroupDescToml(strings.NewReader(serverGroup))
	if err != nil {
		t.Fatal(err)
	}

	if len(group.Roster.List) != 2 {
		t.Fatal("Should have 2 ServerIdentities")
	}
	nikkoAddr := group.Roster.List[0].Address
	if !nikkoAddr.Valid() || nikkoAddr != network.NewTCPAddress("5.135.161.91:2000") {
		t.Fatal("Address not valid " + group.Roster.List[0].Address.String())
	}
	if len(group.Description) != 2 {
		t.Fatal("Should have 2 descriptions")
	}
	if group.Description[group.Roster.List[1]] != "Ismail's server" {
		t.Fatal("This should be Ismail's server")
	}
}
