package onet

import (
	"bytes"
	"testing"
	"time"

	"sync"

	"github.com/dedis/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

const dummyServiceName = "dummyService"
const dummyService2Name = "dummyService2"
const ismServiceName = "ismService"
const backForthServiceName = "backForth"

func init() {
	network.RegisterMessage(SimpleMessageForth{})
	network.RegisterMessage(SimpleMessageBack{})
	network.RegisterMessage(SimpleRequest{})
	dummyMsgType = network.RegisterMessage(DummyMsg{})
	RegisterNewService(ismServiceName, newServiceMessages)
	RegisterNewService(dummyService2Name, newDummyService2)
	GlobalProtocolRegister("DummyProtocol2,", newDummyProtocol2)
}

func TestServiceRegistration(t *testing.T) {
	var name = "dummy"
	RegisterNewService(name, func(c *Context) Service {
		return &DummyService{}
	})

	names := ServiceFactory.RegisteredServiceNames()
	var found bool
	for _, n := range names {
		if n == name {
			found = true
		}
	}
	if !found {
		t.Fatal("Name not found !?")
	}
	ServiceFactory.Unregister(name)
	names = ServiceFactory.RegisteredServiceNames()
	for _, n := range names {
		if n == name {
			t.Fatal("Dummy should not be found!")
		}
	}
}

func TestServiceNew(t *testing.T) {
	ds := &DummyService{
		link: make(chan bool),
	}
	RegisterNewService(dummyServiceName, func(c *Context) Service {
		ds.c = c
		ds.link <- true
		return ds
	})
	defer UnregisterService(dummyServiceName)
	go func() {
		local := NewLocalTest()
		local.GenServers(1)
		defer local.CloseAll()
	}()

	waitOrFatal(ds.link, t)
}

func TestServiceProcessRequest(t *testing.T) {
	link := make(chan bool, 1)
	_, err := RegisterNewService(dummyServiceName, func(c *Context) Service {
		ds := &DummyService{
			link: link,
			c:    c,
		}
		return ds
	})
	log.ErrFatal(err)
	defer UnregisterService(dummyServiceName)

	local := NewTCPTest()
	hs := local.GenServers(2)
	server := hs[0]
	log.Lvl1("Host created and listening")
	defer local.CloseAll()
	// Send a request to the service
	client := NewClient(dummyServiceName)
	log.Lvl1("Sending request to service...")
	_, cerr := client.Send(server.ServerIdentity, "nil", []byte("a"))
	log.Lvl2("Got reply")
	require.Error(t, cerr)
	require.Equal(t, 4100, cerr.ErrorCode())
	require.Equal(t, "wrong message", cerr.ErrorMsg())
	// wait for the link
	if <-link {
		t.Fatal("was expecting false !")
	}
}

// Test if a request that makes the service create a new protocol works
func TestServiceRequestNewProtocol(t *testing.T) {
	ds := &DummyService{
		link: make(chan bool, 1),
	}
	RegisterNewService(dummyServiceName, func(c *Context) Service {
		ds.c = c
		return ds
	})

	defer UnregisterService(dummyServiceName)
	local := NewTCPTest()
	hs := local.GenServers(2)
	server := hs[0]
	client := local.NewClient(dummyServiceName)
	defer local.CloseAll()
	// create the entityList and tree
	el := NewRoster([]*network.ServerIdentity{server.ServerIdentity})
	tree := el.GenerateBinaryTree()
	// give it to the service
	ds.fakeTree = tree

	// Send a request to the service
	log.Lvl1("Sending request to service...")
	log.ErrFatal(client.SendProtobuf(server.ServerIdentity, &DummyMsg{10}, nil))
	// wait for the link from the
	waitOrFatalValue(ds.link, true, t)

	// Now resend the value so we instantiate using the same treenode
	log.Lvl1("Sending request again to service...")
	cerr := client.SendProtobuf(server.ServerIdentity, &DummyMsg{10}, nil)
	assert.Error(t, cerr)
	// this should fail
	waitOrFatalValue(ds.link, false, t)
}

// test for calling the NewProtocol method on a remote Service
func TestServiceNewProtocol(t *testing.T) {
	ds1 := &DummyService{
		link: make(chan bool),
		Config: DummyConfig{
			Send: true,
		},
	}
	ds2 := &DummyService{
		link: make(chan bool),
	}
	var count int
	countMutex := sync.Mutex{}
	RegisterNewService(dummyServiceName, func(c *Context) Service {
		countMutex.Lock()
		defer countMutex.Unlock()
		log.Lvl2("Creating service", count)
		var localDs *DummyService
		switch count {
		case 2:
			// the client does not need a Service
			return &DummyService{link: make(chan bool)}
		case 1: // children
			localDs = ds2
		case 0: // root
			localDs = ds1
		}
		localDs.c = c

		count++
		return localDs
	})

	defer UnregisterService(dummyServiceName)
	local := NewTCPTest()
	defer local.CloseAll()
	hs := local.GenServers(3)
	server1, server2 := hs[0], hs[1]
	client := local.NewClient(dummyServiceName)
	log.Lvl1("Host created and listening")

	// create the entityList and tree
	el := NewRoster([]*network.ServerIdentity{server1.ServerIdentity, server2.ServerIdentity})
	tree := el.GenerateBinaryTree()
	// give it to the service
	ds1.fakeTree = tree

	// Send a request to the service
	log.Lvl1("Sending request to service...")
	log.ErrFatal(client.SendProtobuf(server1.ServerIdentity, &DummyMsg{10}, nil))
	log.Lvl1("Waiting for end")
	// wait for the link from the protocol that Starts
	waitOrFatalValue(ds1.link, true, t)
	// now wait for the second link on the second HOST that the second service
	// should have started (ds2) in ProcessRequest
	waitOrFatalValue(ds2.link, true, t)
	log.Lvl1("Done")
}

func TestServiceProcessor(t *testing.T) {
	ds1 := &DummyService{
		link: make(chan bool),
	}
	ds2 := &DummyService{
		link: make(chan bool),
	}
	var count int
	RegisterNewService(dummyServiceName, func(c *Context) Service {
		var s *DummyService
		if count == 0 {
			s = ds1
		} else {
			s = ds2
		}
		s.c = c
		c.RegisterProcessor(s, dummyMsgType)
		return s
	})
	local := NewLocalTest()
	defer local.CloseAll()
	hs := local.GenServers(2)
	server1, server2 := hs[0], hs[1]

	defer UnregisterService(dummyServiceName)
	// create two servers
	log.Lvl1("Host created and listening")
	// create request
	log.Lvl1("Sending request to service...")
	assert.Nil(t, server2.Send(server1.ServerIdentity, &DummyMsg{10}))

	// wait for the link from the Service on server 1
	waitOrFatalValue(ds1.link, true, t)
}

func TestServiceBackForthProtocol(t *testing.T) {
	local := NewTCPTest()
	defer local.CloseAll()

	// register service
	_, err := RegisterNewService(backForthServiceName, func(c *Context) Service {
		return &simpleService{
			ctx: c,
		}
	})
	log.ErrFatal(err)
	defer ServiceFactory.Unregister(backForthServiceName)

	// create servers
	servers, el, _ := local.GenTree(4, false)

	// create client
	client := local.NewClient(backForthServiceName)

	// create request
	r := &SimpleRequest{
		ServerIdentities: el,
		Val:              10,
	}
	sr := &SimpleResponse{}
	cerr := client.SendProtobuf(servers[0].ServerIdentity, r, sr)
	log.ErrFatal(cerr)
	assert.Equal(t, sr.Val, 10)
}

func TestServiceManager_Service(t *testing.T) {
	local := NewLocalTest()
	defer local.CloseAll()
	servers, _, _ := local.GenTree(2, true)

	services := servers[0].serviceManager.availableServices()
	assert.NotEqual(t, 0, len(services), "no services available")

	service := servers[0].serviceManager.service("testService")
	assert.NotNil(t, service, "Didn't find service testService")
}

func TestServiceMessages(t *testing.T) {
	local := NewLocalTest()
	defer local.CloseAll()
	servers, _, _ := local.GenTree(2, true)

	service := servers[0].serviceManager.service(ismServiceName)
	assert.NotNil(t, service, "Didn't find service ISMService")
	ism := service.(*ServiceMessages)
	ism.SendRaw(servers[0].ServerIdentity, &SimpleResponse{})
	require.True(t, <-ism.GotResponse, "Didn't get response")
}

func TestServiceGenericConfig(t *testing.T) {
	local := NewLocalTest()
	defer local.CloseAll()
	servers, _, tree := local.GenTree(2, true)

	s1 := servers[0].serviceManager.service(dummyService2Name)
	s2 := servers[1].serviceManager.service(dummyService2Name)

	ds1 := s1.(*dummyService2)
	ds2 := s2.(*dummyService2)

	link := make(chan bool)
	ds1.link = link
	ds2.link = link

	// First launch without any config
	go ds1.launchProto(tree, false)
	// wait for the service's protocol creation
	waitOrFatalValue(link, true, t)
	// wait for the service 2 say there is no config
	waitOrFatalValue(link, false, t)
	// then laucnh with config
	go ds1.launchProto(tree, true)
	// wait for the service's protocol creation
	waitOrFatalValue(link, true, t)
	// wait for the service 2 say there is no config
	waitOrFatalValue(link, true, t)

}

// BackForthProtocolForth & Back are messages that go down and up the tree.
// => BackForthProtocol protocol / message
type SimpleMessageForth struct {
	Val int
}

type SimpleMessageBack struct {
	Val int
}

type BackForthProtocol struct {
	*TreeNodeInstance
	Val       int
	counter   int
	forthChan chan struct {
		*TreeNode
		SimpleMessageForth
	}
	backChan chan struct {
		*TreeNode
		SimpleMessageBack
	}
	handler func(val int)
}

func newBackForthProtocolRoot(tn *TreeNodeInstance, val int, handler func(int)) (ProtocolInstance, error) {
	s, err := newBackForthProtocol(tn)
	s.Val = val
	s.handler = handler
	return s, err
}

func newBackForthProtocol(tn *TreeNodeInstance) (*BackForthProtocol, error) {
	s := &BackForthProtocol{
		TreeNodeInstance: tn,
	}
	err := s.RegisterChannel(&s.forthChan)
	if err != nil {
		return nil, err
	}
	err = s.RegisterChannel(&s.backChan)
	if err != nil {
		return nil, err
	}
	go s.dispatch()
	return s, nil
}

func (sp *BackForthProtocol) Start() error {
	// send down to children
	msg := &SimpleMessageForth{
		Val: sp.Val,
	}
	for _, ch := range sp.Children() {
		if err := sp.SendTo(ch, msg); err != nil {
			return err
		}
	}
	return nil
}

func (sp *BackForthProtocol) dispatch() {
	for {
		select {
		// dispatch the first msg down
		case m := <-sp.forthChan:
			msg := &m.SimpleMessageForth
			for _, ch := range sp.Children() {
				sp.SendTo(ch, msg)
			}
			if sp.IsLeaf() {
				if err := sp.SendTo(sp.Parent(), &SimpleMessageBack{msg.Val}); err != nil {
					log.Error(err)
				}
				sp.Done()
				return
			}
		// pass the message up
		case m := <-sp.backChan:
			msg := m.SimpleMessageBack
			// call the handler  if we are the root
			sp.counter++
			if sp.counter == len(sp.Children()) {
				if sp.IsRoot() {
					sp.handler(msg.Val)
				} else {
					sp.SendTo(sp.Parent(), &msg)
				}
				sp.Done()
				return
			}
		}
	}
}

// Client API request / response emulation
type SimpleRequest struct {
	ServerIdentities *Roster
	Val              int
}

type SimpleResponse struct {
	Val int
}

var SimpleResponseType = network.RegisterMessage(SimpleResponse{})

type simpleService struct {
	ctx *Context
}

func (s *simpleService) ProcessClientRequest(path string, buf []byte) ([]byte, ClientError) {
	msg := &SimpleRequest{}
	err := protobuf.DecodeWithConstructors(buf, msg, network.DefaultConstructors(network.S))
	if err != nil {
		return nil, NewClientErrorCode(WebSocketErrorProtobufDecode, "")
	}
	tree := msg.ServerIdentities.GenerateBinaryTree()
	tni := s.ctx.NewTreeNodeInstance(tree, tree.Root, backForthServiceName)
	ret := make(chan int)
	proto, err := newBackForthProtocolRoot(tni, msg.Val, func(n int) {
		ret <- n
	})
	if err != nil {
		return nil, NewClientErrorCode(4100, "")
	}
	if err := s.ctx.RegisterProtocolInstance(proto); err != nil {
		return nil, NewClientErrorCode(4101, "")
	}
	proto.Start()
	resp, err := protobuf.Encode(&SimpleResponse{<-ret})
	if err != nil {
		return nil, NewClientErrorCode(4102, "")
	}
	return resp, nil
}

func (s *simpleService) NewProtocol(tni *TreeNodeInstance, conf *GenericConfig) (ProtocolInstance, error) {
	pi, err := newBackForthProtocol(tni)
	return pi, err
}

func (s *simpleService) Process(env *network.Envelope) {
	return
}

type DummyProtocol struct {
	*TreeNodeInstance
	link   chan bool
	config DummyConfig
}

type DummyConfig struct {
	A    int
	Send bool
}

type DummyMsg struct {
	A int
}

var dummyMsgType network.MessageTypeID

func newDummyProtocol(tni *TreeNodeInstance, conf DummyConfig, link chan bool) *DummyProtocol {
	return &DummyProtocol{tni, link, conf}
}

func (dm *DummyProtocol) Start() error {
	dm.link <- true
	if dm.config.Send {
		// also send to the children if any
		if !dm.IsLeaf() {
			if err := dm.SendToChildren(&DummyMsg{}); err != nil {
				log.Error(err)
			}
		}
	}
	return nil
}

func (dm *DummyProtocol) ProcessProtocolMsg(msg *ProtocolMsg) {
	dm.link <- true
}

// legacy reasons
func (dm *DummyProtocol) Dispatch() error {
	return nil
}

type DummyService struct {
	c        *Context
	link     chan bool
	fakeTree *Tree
	firstTni *TreeNodeInstance
	Config   DummyConfig
}

func (ds *DummyService) ProcessClientRequest(path string, buf []byte) ([]byte, ClientError) {
	log.Lvl2("Got called with path", path, buf)
	msg := &DummyMsg{}
	err := protobuf.Decode(buf, msg)
	if err != nil {
		ds.link <- false
		return nil, NewClientErrorCode(4100, "wrong message")
	}
	if ds.firstTni == nil {
		ds.firstTni = ds.c.NewTreeNodeInstance(ds.fakeTree, ds.fakeTree.Root, dummyServiceName)
	}

	dp := newDummyProtocol(ds.firstTni, ds.Config, ds.link)

	if err := ds.c.RegisterProtocolInstance(dp); err != nil {
		ds.link <- false
		return nil, NewClientErrorCode(4101, "")
	}
	log.Lvl2("Starting protocol")
	go dp.Start()
	return nil, nil
}

func (ds *DummyService) NewProtocol(tn *TreeNodeInstance, conf *GenericConfig) (ProtocolInstance, error) {
	dp := newDummyProtocol(tn, DummyConfig{}, ds.link)
	return dp, nil
}

func (ds *DummyService) Process(env *network.Envelope) {
	if !env.MsgType.Equal(dummyMsgType) {
		ds.link <- false
		return
	}
	dms := env.Msg.(*DummyMsg)
	if dms.A != 10 {
		ds.link <- false
		return
	}
	ds.link <- true
}

type ServiceMessages struct {
	*ServiceProcessor
	GotResponse chan bool
}

func (i *ServiceMessages) SimpleResponse(env *network.Envelope) {
	i.GotResponse <- true
}

func newServiceMessages(c *Context) Service {
	s := &ServiceMessages{
		ServiceProcessor: NewServiceProcessor(c),
		GotResponse:      make(chan bool),
	}
	c.RegisterProcessorFunc(SimpleResponseType, s.SimpleResponse)
	return s
}

type dummyService2 struct {
	*Context
	link chan bool
}

func newDummyService2(c *Context) Service {
	return &dummyService2{Context: c}
}

func (ds *dummyService2) ProcessClientRequest(path string, buf []byte) ([]byte, ClientError) {
	panic("should not be called")
}

var serviceConfig = []byte{0x01, 0x02, 0x03, 0x04}

func (ds *dummyService2) NewProtocol(tn *TreeNodeInstance, conf *GenericConfig) (ProtocolInstance, error) {
	ds.link <- conf != nil && bytes.Equal(conf.Data, serviceConfig)
	return newDummyProtocol2(tn)
}

func (ds *dummyService2) Process(env *network.Envelope) {
	panic("should not be called")
}

func (ds *dummyService2) launchProto(t *Tree, config bool) {
	tni := ds.NewTreeNodeInstance(t, t.Root, dummyService2Name)
	pi, err := newDummyProtocol2(tni)
	err2 := ds.RegisterProtocolInstance(pi)
	ds.link <- err == nil && err2 == nil

	if config {
		tni.SetConfig(&GenericConfig{serviceConfig})
	}
	go pi.Start()
}

type DummyProtocol2 struct {
	*TreeNodeInstance
	c chan WrapDummyMsg
}

type WrapDummyMsg struct {
	*TreeNode
	DummyMsg
}

func newDummyProtocol2(n *TreeNodeInstance) (ProtocolInstance, error) {
	d := &DummyProtocol2{TreeNodeInstance: n}
	d.c = make(chan WrapDummyMsg, 1)
	d.RegisterChannel(d.c)
	return d, nil
}

func (dp2 *DummyProtocol2) Start() error {
	return dp2.SendToChildren(&DummyMsg{20})
}

func waitOrFatalValue(ch chan bool, v bool, t *testing.T) {
	select {
	case b := <-ch:
		if v != b {
			t.Fatal("Wrong value returned on channel")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Waited too long")
	}

}

func waitOrFatal(ch chan bool, t *testing.T) {
	select {
	case _ = <-ch:
		return
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Waited too long")
	}
}
