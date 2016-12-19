package onet

import (
	"testing"

	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/assert"
)

func init() {
	GlobalProtocolRegister(spawnName, newSpawnProto)
}

func TestTreeNodeCreateProtocol(t *testing.T) {
	local := NewLocalTest()
	defer local.CloseAll()

	hosts, _, tree := local.GenTree(1, true)
	pi, err := hosts[0].overlay.CreateProtocolOnet(spawnName, tree)
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
	pi, err := hosts[0].overlay.CreateProtocolOnet(spawnName, tree)
	log.ErrFatal(err)
	p := pi.(*spawnProto)
	assert.NotNil(t, p.RegisterHandler(p.HandlerError1))
	assert.Nil(t, p.RegisterHandler(p.HandlerError2))
	assert.NotNil(t, p.RegisterHandler(p.HandlerError3))
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
