package onet

import (
	"testing"

	"github.com/dedis/kyber/suites"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/stretchr/testify/require"
)

var tSuite = suites.MustFind("Ed25519")

const clientServiceName = "ClientService"

func init() {
	RegisterNewService(clientServiceName, newClientService)
}

func Test_panicClose(t *testing.T) {
	l := NewLocalTest(tSuite)
	l.CloseAll()
	require.Panics(t, func() { l.genLocalHosts(2) })
}

func TestGenLocalHost(t *testing.T) {
	l := NewLocalTest(tSuite)
	hosts := l.genLocalHosts(2)
	defer l.CloseAll()

	log.Lvl4("Hosts are:", hosts[0].Address(), hosts[1].Address())
	if hosts[0].Address() == hosts[1].Address() {
		t.Fatal("Both addresses are equal")
	}
}

// This tests the client-connection in the case of a non-garbage-collected
// client that stays in the service.
func TestNewTCPTest(t *testing.T) {
	l := NewTCPTest(tSuite)
	_, el, _ := l.GenTree(3, true)
	defer l.CloseAll()

	c1 := NewClient(tSuite, clientServiceName)
	err := c1.SendProtobuf(el.List[0], &SimpleMessage{}, nil)
	log.ErrFatal(err)
}

type clientService struct {
	*ServiceProcessor
	cl *Client
}

type SimpleMessage2 struct{}

func (c *clientService) SimpleMessage(msg *SimpleMessage) (network.Message, error) {
	log.Lvl3("Got request", msg)
	c.cl.SendProtobuf(c.ServerIdentity(), &SimpleMessage2{}, nil)
	return nil, nil
}

func (c *clientService) SimpleMessage2(msg *SimpleMessage2) (network.Message, error) {
	log.Lvl3("Got request", msg)
	return nil, nil
}

func newClientService(c *Context) (Service, error) {
	s := &clientService{
		ServiceProcessor: NewServiceProcessor(c),
		cl:               NewClient(c.server.Suite(), clientServiceName),
	}
	log.ErrFatal(s.RegisterHandlers(s.SimpleMessage, s.SimpleMessage2))
	return s, nil
}
