package manage

import (
	"testing"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

// Tests a 2-node system
func TestCount(t *testing.T) {
	local := onet.NewLocalTest(tSuite)
	nbrNodes := 2
	_, _, tree := local.GenTree(nbrNodes, true)
	defer local.CloseAll()

	pi, err := local.StartProtocol("Count", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := pi.(*ProtocolCount)
	// https://stackoverflow.com/questions/17573190/how-to-multiply-duration-by-integer
	// "You really have to do Duration * Duration which is horrible."
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*nbrNodes*2)
	select {
	case children := <-protocol.Count:
		log.Lvl2("Instance 1 is done")
		if children != nbrNodes {
			t.Fatal("Didn't get a child-cound of", nbrNodes)
		}
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}
