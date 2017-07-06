package onet

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

func init() {
	GlobalProtocolRegister(spawnName, newSpawnProto)
}

func TestTreeNodeCreateProtocol(t *testing.T) {
	local := NewLocalTest()
	defer local.CloseAll()

	hosts, _, tree := local.GenTree(1, true)
	pi, err := hosts[0].overlay.CreateProtocol(spawnName, tree, NilServiceID)
	log.ErrFatal(err)
	p := pi.(*spawnProto)
	p.spawn = true
	go p.Start()

	// wait once for the protocol just created
	<-spawnCh
	// wait once more for the protocol created inside the first one
	<-spawnCh
}

func TestHandlerReturn(t *testing.T) {
	local := NewLocalTest()
	defer local.CloseAll()

	hosts, _, tree := local.GenTree(1, true)
	pi, err := hosts[0].overlay.CreateProtocol(spawnName, tree, NilServiceID)
	log.ErrFatal(err)
	p := pi.(*spawnProto)
	assert.NotNil(t, p.RegisterHandler(p.HandlerError1))
	assert.Nil(t, p.RegisterHandler(p.HandlerError2))
	assert.NotNil(t, p.RegisterHandler(p.HandlerError3))
}

type dummyMsg struct{}

type configProcessor struct {
	configCount int
	expected    int
	done        chan<- bool
}

func (p *configProcessor) Process(env *network.Envelope) {
	if env.MsgType == ConfigMsgID {
		p.configCount++
		if p.configCount == p.expected {
			p.done <- true
		}
	}
}

func TestConfigPropagation(t *testing.T) {
	local := NewLocalTest()
	defer local.CloseAll()
	const treeSize = 3
	var serviceConfig = []byte{0x01, 0x02, 0x03, 0x04}
	hosts, _, tree := local.GenTree(treeSize, true)
	_, err := hosts[0].overlay.CreateProtocol(spawnName, tree, NilServiceID)
	log.ErrFatal(err)

	done := make(chan bool)
	pr := &configProcessor{expected: treeSize - 1, done: done}

	for _, host := range hosts {
		host.RegisterProcessor(pr,
			ProtocolMsgID,
			RequestTreeMsgID,
			SendTreeMsgID,
			RequestRosterMsgID,
			SendRosterMsgID,
			ConfigMsgID)
	}

	network.RegisterMessage(dummyMsg{})
	rootInstance, _ := local.NewTreeNodeInstance(tree.Root, spawnName)
	err = rootInstance.SetConfig(&GenericConfig{serviceConfig})
	assert.Nil(t, err)
	err = rootInstance.SetConfig(&GenericConfig{serviceConfig})
	assert.NotNil(t, err)
	err = rootInstance.SendToChildren(&dummyMsg{})
	log.ErrFatal(err)
	// wait until the processor has processed the expected number of config messages
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Didn't receive response in time")
	}

}

// spawnCh is used to dispatch information from a spawnProto to the test
var spawnCh = make(chan bool)

const spawnName = "Spawn"

// spawnProto is a simple protocol which just spawn another protocol when
// started
type spawnProto struct {
	*TreeNodeInstance
	spawn bool
}

func newSpawnProto(tn *TreeNodeInstance) (ProtocolInstance, error) {
	return &spawnProto{
		TreeNodeInstance: tn,
	}, nil
}

func (s *spawnProto) Start() error {
	r := s.Roster()
	tree := r.GenerateBinaryTree()
	spawnCh <- true
	if !s.spawn {
		return nil
	}
	proto, err := s.CreateProtocol(spawnName, tree)
	log.ErrFatal(err)
	go proto.Start()
	return nil
}

type spawnMsg struct {
	*TreeNode
	I int
}

// Invalid handler
func (s *spawnProto) HandlerError1(msg spawnMsg) {}

// Valid handler
func (s *spawnProto) HandlerError2(msg spawnMsg) error {
	return nil
}

// Invalid handler
func (s *spawnProto) HandlerError3(msg spawnMsg) (int, error) {
	return 0, nil
}
