package onet

import (
	"net/http"
	"testing"

	"fmt"

	"sync"

	"github.com/dedis/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
	"gopkg.in/satori/go.uuid.v1"
)

func init() {
	RegisterNewService(serviceWebSocket, newServiceWebSocket)
}

func TestNewWebSocket(t *testing.T) {
	l := NewLocalTest(tSuite)
	defer l.CloseAll()

	c := newTCPServer(tSuite, 0, l.path)
	defer c.Close()
	require.Equal(t, len(c.serviceManager.services), len(c.websocket.services))
	require.NotEmpty(t, c.websocket.services[serviceWebSocket])
	url, err := getWebAddress(c.ServerIdentity, false)
	log.ErrFatal(err)
	ws, err := websocket.Dial(fmt.Sprintf("ws://%s/WebSocket/SimpleResponse", url),
		"", "http://something_else")
	log.ErrFatal(err)
	req := &SimpleResponse{}
	log.Lvlf1("Sending message Request: %x", uuid.UUID(network.MessageType(req)).Bytes())
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
	local := NewTCPTest(tSuite)
	defer local.CloseAll()

	// register service
	RegisterNewService(backForthServiceName, func(c *Context) (Service, error) {
		return &simpleService{
			ctx: c,
		}, nil
	})
	defer ServiceFactory.Unregister(backForthServiceName)

	// create servers
	servers, el, _ := local.GenTree(4, false)
	client := local.NewClient(backForthServiceName)

	r := &SimpleRequest{
		ServerIdentities: el,
		Val:              10,
	}
	sr := &SimpleResponse{}
	assert.Equal(t, uint64(0), client.Rx())
	assert.Equal(t, uint64(0), client.Tx())
	log.ErrFatal(client.SendProtobuf(servers[0].ServerIdentity, r, sr))
	assert.Equal(t, sr.Val, 10)
	assert.NotEqual(t, uint64(0), client.Rx())
	assert.NotEqual(t, uint64(0), client.Tx())
	assert.True(t, client.Tx() > client.Rx())
}

func TestClient_Parallel(t *testing.T) {
	nbrNodes := 4
	nbrParallel := 20
	local := NewTCPTest(tSuite)
	defer local.CloseAll()

	// register service
	RegisterNewService(backForthServiceName, func(c *Context) (Service, error) {
		return &simpleService{
			ctx: c,
		}, nil
	})
	defer ServiceFactory.Unregister(backForthServiceName)

	// create servers
	servers, el, _ := local.GenTree(nbrNodes, true)

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
			log.ErrFatal(client.SendProtobuf(servers[0].ServerIdentity, r, sr))
			assert.Equal(t, 10*i, sr.Val)
			log.Lvl1("Done with message", i)
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func TestNewClientKeep(t *testing.T) {
	c := NewClientKeep(tSuite, serviceWebSocket)
	assert.True(t, c.keep)
}

func TestMultiplePath(t *testing.T) {
	_, err := RegisterNewService(dummyService3Name, func(c *Context) (Service, error) {
		ds := &DummyService3{}
		return ds, nil
	})
	log.ErrFatal(err)
	defer UnregisterService(dummyService3Name)

	local := NewTCPTest(tSuite)
	hs := local.GenServers(2)
	server := hs[0]
	defer local.CloseAll()
	client := NewClientKeep(tSuite, dummyService3Name)
	msg, err := protobuf.Encode(&DummyMsg{})
	require.Nil(t, err)
	path1, path2 := "path1", "path2"
	resp, err := client.Send(server.ServerIdentity, path1, msg)
	require.Nil(t, err)
	require.Equal(t, path1, string(resp))
	resp, err = client.Send(server.ServerIdentity, path2, msg)
	require.Nil(t, err)
	require.Equal(t, path2, string(resp))
}

func TestWebSocket_Error(t *testing.T) {
	client := NewClientKeep(tSuite, dummyService3Name)
	local := NewTCPTest(tSuite)
	hs := local.GenServers(2)
	server := hs[0]
	defer local.CloseAll()

	log.OutputToBuf()
	_, err := client.Send(server.ServerIdentity, "test", nil)
	log.OutputToOs()
	require.NotEqual(t, "websocket: bad handshake", err.Error())
	assert.NotEqual(t, "", log.GetStdOut())
}

const serviceWebSocket = "WebSocket"

type ServiceWebSocket struct {
	*ServiceProcessor
}

func (i *ServiceWebSocket) SimpleResponse(msg *SimpleResponse) (network.Message, error) {
	return &SimpleResponse{msg.Val + 1}, nil
}

func newServiceWebSocket(c *Context) (Service, error) {
	s := &ServiceWebSocket{
		ServiceProcessor: NewServiceProcessor(c),
	}
	log.ErrFatal(s.RegisterHandler(s.SimpleResponse))
	return s, nil
}

const dummyService3Name = "dummyService3"

type DummyService3 struct {
}

func (ds *DummyService3) ProcessClientRequest(req *http.Request, path string, buf []byte) ([]byte, error) {
	log.Lvl2("Got called with path", path, buf)
	return []byte(path), nil
}

func (ds *DummyService3) NewProtocol(tn *TreeNodeInstance, conf *GenericConfig) (ProtocolInstance, error) {
	return nil, nil
}

func (ds *DummyService3) Process(env *network.Envelope) {
}
