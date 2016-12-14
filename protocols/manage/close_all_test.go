package manage_test

import (
	"testing"

	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
)

// Tests a 2-node system
func TestCloseAll(t *testing.T) {
	local := onet.NewLocalTest()
	defer log.AfterTest(t)
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
