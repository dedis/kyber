package onet

import (
	"testing"

	"reflect"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testServiceName = "testService"

func init() {
	RegisterNewService(testServiceName, newTestService)
	ServiceFactory.ServiceID(testServiceName)
	network.RegisterMessage(&testMsg{})
}

func TestProcessor_AddMessage(t *testing.T) {
	h1 := NewLocalServer(2000)
	defer h1.Close()
	p := NewServiceProcessor(&Context{server: h1})
	log.ErrFatal(p.RegisterHandler(procMsg))
	if len(p.handlers) != 1 {
		t.Fatal("Should have registered one function")
	}
	mt := network.MessageType(&testMsg{})
	if mt == network.ErrorType {
		t.Fatal("Didn't register message-type correctly")
	}
	var wrongFunctions = []interface{}{
		procMsgWrong1,
		procMsgWrong2,
		procMsgWrong3,
		procMsgWrong4,
	}
	for _, f := range wrongFunctions {
		fsig := reflect.TypeOf(f).String()
		log.Lvl2("Checking function", fsig)
		assert.Error(t, p.RegisterHandler(f),
			"Could register wrong function: "+fsig)
	}
}

func TestProcessor_RegisterMessages(t *testing.T) {
	h1 := NewLocalServer(2000)
	defer h1.Close()
	p := NewServiceProcessor(&Context{server: h1})
	log.ErrFatal(p.RegisterHandlers(procMsg, procMsg2))
	assert.Error(t, p.RegisterHandlers(procMsg3, procMsgWrong4))
}

func TestServiceProcessor_ProcessClientRequest(t *testing.T) {
	h1 := NewLocalServer(2000)
	defer h1.Close()
	p := NewServiceProcessor(&Context{server: h1})
	log.ErrFatal(p.RegisterHandler(procMsg))

	buf, err := protobuf.Encode(&testMsg{11})
	log.ErrFatal(err)
	rep, cerr := p.ProcessClientRequest("testMsg", buf)
	require.Equal(t, nil, cerr)
	val := &testMsg{}
	log.ErrFatal(protobuf.Decode(rep, val))
	if val.I != 11 {
		t.Fatal("Value got lost - should be 11")
	}

	buf, err = protobuf.Encode(&testMsg{42})
	log.ErrFatal(err)
	rep, cerr = p.ProcessClientRequest("testMsg", buf)
	require.Equal(t, 4142, cerr.ErrorCode())
}

func TestProcessor_ProcessClientRequest(t *testing.T) {
	local := NewTCPTest()

	// generate 5 hosts,
	h := local.GenServers(1)[0]
	defer local.CloseAll()

	client := local.NewClient(testServiceName)
	msg := &testMsg{}
	cerr := client.SendProtobuf(h.ServerIdentity, &testMsg{12}, msg)
	log.ErrFatal(cerr)
	if msg == nil {
		t.Fatal("Msg should not be nil")
	}
	if msg.I != 12 {
		t.Fatal("Didn't send 12")
	}
}

type testMsg struct {
	I int
}

type testMsg2 testMsg
type testMsg3 testMsg
type testMsg4 testMsg
type testMsg5 testMsg

func procMsg(msg *testMsg) (network.Message, ClientError) {
	// Return an error for testing
	if msg.I == 42 {
		return nil, NewClientErrorCode(4142, "")
	}
	return msg, nil
}

func procMsg2(msg *testMsg2) (network.Message, ClientError) {
	return nil, nil
}
func procMsg3(msg *testMsg3) (network.Message, ClientError) {
	return nil, nil
}

func procMsgWrong1() (network.Message, ClientError) {
	return nil, nil
}

func procMsgWrong2(msg testMsg2) (network.Message, ClientError) {
	return msg, nil
}

func procMsgWrong3(msg *testMsg3) ClientError {
	return nil
}

func procMsgWrong4(msg *testMsg4) (ClientError, network.Message) {
	return nil, msg
}

type testService struct {
	*ServiceProcessor
	Msg interface{}
}

func newTestService(c *Context) Service {
	ts := &testService{
		ServiceProcessor: NewServiceProcessor(c),
	}
	log.ErrFatal(ts.RegisterHandler(ts.ProcessMsg))
	return ts
}

func (ts *testService) NewProtocol(tn *TreeNodeInstance, conf *GenericConfig) (ProtocolInstance, error) {
	return nil, nil
}

func (ts *testService) ProcessMsg(msg *testMsg) (network.Message, ClientError) {
	ts.Msg = msg
	return msg, nil
}
