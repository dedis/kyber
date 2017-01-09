package onet

import (
	"testing"

	"fmt"

	"errors"

	"sync"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/protobuf"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
)

func init() {
	RegisterNewService(serviceWebSocket, newServiceWebSocket)
}

func TestNewWebSocket(t *testing.T) {
	c := NewTCPConode(0)
	defer c.Close()
	require.Equal(t, len(c.serviceManager.services), len(c.websocket.services))
	require.NotEmpty(t, c.websocket.services[serviceWebSocket])
	url, err := getWebAddress(c.ServerIdentity, false)
	log.ErrFatal(err)
	ws, err := websocket.Dial(fmt.Sprintf("ws://%s/WebSocket/SimpleResponse", url),
		"", "http://"+url)
	log.ErrFatal(err)
	req := &SimpleResponse{}
	log.Lvlf1("Sending message Request: %x", uuid.UUID(network.TypeFromData(req)).Bytes())
	buf, err := protobuf.Encode(req)
	log.ErrFatal(err)
	log.ErrFatal(websocket.Message.Send(ws, buf))

	log.Lvl1("Waiting for reply")
	var rcv []byte
	log.ErrFatal(websocket.Message.Receive(ws, &rcv))
	log.Lvlf1("Received reply: %x", rcv)
	rcvMsg := &SimpleResponse{}
	log.ErrFatal(protobuf.Decode(rcv, rcvMsg))
	assert.Equal(t, 1, rcvMsg.Val)
}

func TestGetWebHost(t *testing.T) {
	url, err := getWebAddress(&network.ServerIdentity{Address: "tcp://8.8.8.8"}, true)
	require.NotNil(t, err)
	url, err = getWebAddress(&network.ServerIdentity{Address: "tcp://8.8.8.8"}, false)
	require.NotNil(t, err)
	url, err = getWebAddress(&network.ServerIdentity{Address: "tcp://8.8.8.8:7770"}, true)
	log.ErrFatal(err)
	require.Equal(t, "0.0.0.0:7771", url)
	url, err = getWebAddress(&network.ServerIdentity{Address: "tcp://8.8.8.8:7770"}, false)
	log.ErrFatal(err)
	require.Equal(t, "8.8.8.8:7771", url)
}

func TestClient_Send(t *testing.T) {
	local := NewTCPTest()
	defer local.CloseAll()

	// register service
	RegisterNewService(backForthServiceName, func(c *Context, path string) Service {
		return &simpleService{
			ctx: c,
		}
	})
	defer ServiceFactory.Unregister(backForthServiceName)

	// create conodes
	conodes, el, _ := local.GenTree(4, false)
	client := local.NewClient(backForthServiceName)

	r := &SimpleRequest{
		ServerIdentities: el,
		Val:              10,
	}
	sr := &SimpleResponse{}
	log.ErrFatal(client.SendProtobuf(conodes[0].ServerIdentity, r, sr))
	assert.Equal(t, sr.Val, 10)
}

func TestClient_Parallel(t *testing.T) {
	nbrNodes := 4
	nbrParallel := 20
	local := NewTCPTest()
	defer local.CloseAll()

	// register service
	RegisterNewService(backForthServiceName, func(c *Context, path string) Service {
		return &simpleService{
			ctx: c,
		}
	})
	defer ServiceFactory.Unregister(backForthServiceName)

	// create conodes
	conodes, el, _ := local.GenTree(nbrNodes, true)

	wg := sync.WaitGroup{}
	wg.Add(nbrParallel)
	for i := 0; i < nbrParallel; i++ {
		go func(i int) {
			log.Lvl1("Starting message", i)
			r := &SimpleRequest{
				ServerIdentities: el,
				Val:              10 * i,
			}
			client := local.NewClient(backForthServiceName)
			sr := &SimpleResponse{}
			log.ErrFatal(client.SendProtobuf(conodes[0].ServerIdentity, r, sr))
			assert.Equal(t, 10*i, sr.Val)
			log.Lvl1("Done with message", i)
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func TestNewClientError(t *testing.T) {
	ce := NewClientError(errors.New("websocket:close 1100: hello"))
	assert.Equal(t, 0, ce.ErrorCode())
	needsColumn := "websocket: close 1100:"
	ce = NewClientError(errors.New(needsColumn))
	assert.Equal(t, 1100, ce.ErrorCode())
	assert.Equal(t, "", ce.ErrorMsg())
	str := "websocket: close 1100: hello"
	ce = NewClientError(errors.New(str))
	assert.Equal(t, 1100, ce.ErrorCode())
	assert.Equal(t, "hello", ce.ErrorMsg())
	assert.Equal(t, str, ce.Error())

	assert.True(t, NewClientError(nil) == nil)
	assert.True(t, NewClientError((error)(nil)) == nil)
}

func TestNewClientKeep(t *testing.T) {
	c := NewClientKeep(serviceWebSocket)
	assert.True(t, c.keep)
}

const serviceWebSocket = "WebSocket"

type ServiceWebSocket struct {
	*ServiceProcessor
}

func (i *ServiceWebSocket) SimpleResponse(msg *SimpleResponse) (network.Message, ClientError) {
	return &SimpleResponse{msg.Val + 1}, nil
}

func newServiceWebSocket(c *Context, path string) Service {
	s := &ServiceWebSocket{
		ServiceProcessor: NewServiceProcessor(c),
	}
	log.ErrFatal(s.RegisterHandler(s.SimpleResponse))
	return s
}
