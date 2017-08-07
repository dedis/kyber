package manage

import (
	"testing"

	"gopkg.in/dedis/kyber.v1/group/edwards25519"

	"time"

	"gopkg.in/dedis/onet.v2"
)

var suite = edwards25519.NewAES128SHA256Ed25519()

// Tests a 2-node system
func TestCloseAll(t *testing.T) {
	local := onet.NewLocalTest(suite)
	//defer log.AfterTest(t)
	nbrNodes := 2
	_, _, tree := local.GenTree(nbrNodes, true)
	defer local.CloseAll()

	pi, err := local.CreateProtocol("CloseAll", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	done := make(chan bool)
	go func() {
		pi.Start()
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Didn't finish in 10 seconds")
	}
}
