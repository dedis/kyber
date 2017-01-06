package onet

import (
	"testing"

	"github.com/dedis/onet/log"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
)

func TestConode_ProtocolRegisterName(t *testing.T) {
	c := NewLocalConode(0)
	defer c.Close()
	plen := len(c.protocols.instantiators)
	require.True(t, plen > 0)
	id, err := c.ProtocolRegister("ConodeProtocol", NewConodeProtocol)
	log.ErrFatal(err)
	require.NotNil(t, id)
	require.True(t, plen < len(c.protocols.instantiators))
	_, err = c.protocolInstantiate(ProtocolID(uuid.Nil), nil)
	require.NotNil(t, err)
	// Test for not overwriting
	_, err = c.ProtocolRegister("ConodeProtocol", NewConodeProtocol2)
	require.NotNil(t, err)
}

func TestConode_GetService(t *testing.T) {
	c := NewLocalConode(0)
	defer c.Close()
	s := c.GetService("nil")
	require.Nil(t, s)
}

type ConodeProtocol struct {
	*TreeNodeInstance
}

// NewExampleHandlers initialises the structure for use in one round
func NewConodeProtocol(n *TreeNodeInstance) (ProtocolInstance, error) {
	return &ConodeProtocol{n}, nil
}

// NewExampleHandlers initialises the structure for use in one round
func NewConodeProtocol2(n *TreeNodeInstance) (ProtocolInstance, error) {
	return &ConodeProtocol{n}, nil
}

func (cp *ConodeProtocol) Start() error {
	return nil
}
