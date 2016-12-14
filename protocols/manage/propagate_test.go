package manage

import (
	"sync"
	"testing"

	"bytes"

	"reflect"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

type PropagateMsg struct {
	Data []byte
}

func init() {
	network.RegisterPacketType(PropagateMsg{})
}

// Tests an n-node system
func TestPropagate(t *testing.T) {
	for _, nbrNodes := range []int{3, 10, 14} {
		local := onet.NewLocalTest()
		conodes, el, _ := local.GenTree(nbrNodes, true)
		var i int
		var iMut sync.Mutex
		msg := &PropagateMsg{[]byte("propagate")}
		propFuncs := make([]PropagationFunc, nbrNodes)
		var err error
		for n, conode := range conodes {
			pc := &PC{conode, local.Overlays[conode.ServerIdentity.ID]}
			propFuncs[n], err = NewPropagationFunc(pc,
				"Propagate",
				func(m network.Body) {
					if bytes.Equal(msg.Data, m.(*PropagateMsg).Data) {
						iMut.Lock()
						i++
						iMut.Unlock()
					} else {
						t.Error("Didn't receive correct data")
					}
				})
			log.ErrFatal(err)
		}
		log.Lvl2("Starting to propagate", reflect.TypeOf(msg))
		children, err := propFuncs[0](el, msg, 1000)
		log.ErrFatal(err)

		if i != nbrNodes {
			t.Fatal("Didn't get data-request")
		}
		if children != nbrNodes {
			t.Fatal("Not all nodes replied")
		}
		local.CloseAll()
		log.AfterTest(t)
	}
}

type PC struct {
	C *onet.Conode
	O *onet.Overlay
}

func (pc *PC) ProtocolRegister(name string, protocol onet.NewProtocol) (onet.ProtocolID, error) {
	return pc.C.ProtocolRegister(name, protocol)
}
func (pc *PC) ServerIdentity() *network.ServerIdentity {
	return pc.C.ServerIdentity

}
func (pc *PC) CreateProtocolSDA(name string, t *onet.Tree) (onet.ProtocolInstance, error) {
	return pc.O.CreateProtocolSDA(name, t)
}
