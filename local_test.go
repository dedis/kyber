package onet

import (
	"testing"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

const clientServiceName = "ClientService"

func init() {
	RegisterNewService(clientServiceName, newClientService)
}

func TestGenLocalHost(t *testing.T) {
	l := NewLocalTest()
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
	l := NewTCPTest()
	_, el, _ := l.GenTree(3, true)
	defer l.CloseAll()

	c1 := NewClient(clientServiceName)
	cerr := c1.SendProtobuf(el.List[0], &SimpleMessage{}, nil)
	log.ErrFatal(cerr)
}

type clientService struct {
	*ServiceProcessor
	cl *Client
}

type SimpleMessage2 struct{}

func (c *clientService) SimpleMessage(msg *SimpleMessage) (network.Message, ClientError) {
	log.Lvl3("Got request", msg)
	c.cl.SendProtobuf(c.ServerIdentity(), &SimpleMessage2{}, nil)
	return nil, nil
}

func (c *clientService) SimpleMessage2(msg *SimpleMessage2) (network.Message, ClientError) {
	log.Lvl3("Got request", msg)
	return nil, nil
}

func newClientService(c *Context, path string) Service {
	s := &clientService{
		ServiceProcessor: NewServiceProcessor(c),
		cl:               NewClient(clientServiceName),
	}
	log.ErrFatal(s.RegisterHandlers(s.SimpleMessage, s.SimpleMessage2))
	return s
}
