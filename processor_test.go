package onet

import (
	"errors"
	"testing"

	"reflect"

	"github.com/dedis/protobuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

const testServiceName = "testService"

func init() {
	RegisterNewService(testServiceName, newTestService)
	ServiceFactory.ServiceID(testServiceName)
	network.RegisterMessage(&testMsg{})
}

func TestProcessor_AddMessage(t *testing.T) {
	h1 := NewLocalServer(tSuite, 2000)
	defer h1.Close()
	p := NewServiceProcessor(&Context{server: h1})
	log.ErrFatal(p.RegisterHandler(procMsg))
	if len(p.handlers) != 1 {
		t.Fatal("Should have registered one function")
	}
	mt := network.MessageType(&testMsg{})
	if mt.Equal(network.ErrorType) {
		t.Fatal("Didn't register message-type correctly")
	}
	var wrongFunctions = []interface{}{
		procMsgWrong1,
		procMsgWrong2,
		procMsgWrong3,
		procMsgWrong4,
		procMsgWrong5,
		procMsgWrong6,
		procMsgWrong7,
	}
	for _, f := range wrongFunctions {
		fsig := reflect.TypeOf(f).String()
		log.Lvl2("Checking function", fsig)
		assert.Error(t, p.RegisterHandler(f),
			"Could register wrong function: "+fsig)
	}
}

func TestProcessor_RegisterMessages(t *testing.T) {
	h1 := NewLocalServer(tSuite, 2000)
	defer h1.Close()
	p := NewServiceProcessor(&Context{server: h1})
	log.ErrFatal(p.RegisterHandlers(procMsg, procMsg2, procMsg3, procMsg4))
	assert.Error(t, p.RegisterHandlers(procMsg3, procMsgWrong4))
}

func TestServiceProcessor_ProcessClientRequest(t *testing.T) {
	h1 := NewLocalServer(tSuite, 2000)
	defer h1.Close()
	p := NewServiceProcessor(&Context{server: h1})
	log.ErrFatal(p.RegisterHandlers(procMsg, procMsg2))

	buf, err := protobuf.Encode(&testMsg{11})
	log.ErrFatal(err)
	rep, err := p.ProcessClientRequest(nil, "testMsg", buf)
	require.Equal(t, nil, err)
	val := &testMsg{}
	log.ErrFatal(protobuf.Decode(rep, val))
	if val.I != 11 {
		t.Fatal("Value got lost - should be 11")
	}

	buf, err = protobuf.Encode(&testMsg{42})
	log.ErrFatal(err)
	_, err = p.ProcessClientRequest(nil, "testMsg", buf)
	assert.NotNil(t, err)

	buf, err = protobuf.Encode(&testMsg2{42})
	log.ErrFatal(err)
	_, err = p.ProcessClientRequest(nil, "testMsg2", buf)
	assert.NotNil(t, err)

	// Test non-existing endpoint
	buf, err = protobuf.Encode(&testMsg2{42})
	log.ErrFatal(err)
	log.OutputToBuf()
	_, err = p.ProcessClientRequest(nil, "testMsgNotAvailable", buf)
	log.OutputToOs()
	assert.NotNil(t, err)
	assert.NotEqual(t, "", log.GetStdOut())
}

func TestProcessor_ProcessClientRequest(t *testing.T) {
	local := NewTCPTest(tSuite)

	// generate 5 hosts,
	h := local.GenServers(1)[0]
	defer local.CloseAll()

	client := local.NewClient(testServiceName)
	msg := &testMsg{}
	err := client.SendProtobuf(h.ServerIdentity, &testMsg{12}, msg)
	log.ErrFatal(err)
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

func procMsg(msg *testMsg) (network.Message, error) {
	// Return an error for testing
	if msg.I == 42 {
		return nil, errors.New("42 is NOT the answer")
	}
	return msg, nil
}

func procMsg2(msg *testMsg2) (network.Message, error) {
	// Return an error for testing
	if msg.I == 42 {
		return nil, errors.New("42 is NOT the answer")
	}
	return nil, nil
}
func procMsg3(msg *testMsg3) (network.Message, error) {
	return nil, nil
}
func procMsg4(msg *testMsg4) (*testMsg4, error) {
	return msg, nil
}

func procMsgWrong1() (network.Message, error) {
	return nil, nil
}

func procMsgWrong2(msg testMsg2) (network.Message, error) {
	return msg, nil
}

func procMsgWrong3(msg *testMsg3) error {
	return nil
}

func procMsgWrong4(msg *testMsg4) (error, network.Message) {
	return nil, msg
}

func procMsgWrong5(msg *testMsg) (*network.Message, error) {
	return nil, nil
}

func procMsgWrong6(msg *testMsg) (int, error) {
	return 10, nil
}
func procMsgWrong7(msg *testMsg) (testMsg, error) {
	return *msg, nil
}

type testService struct {
	*ServiceProcessor
	Msg interface{}
}

func newTestService(c *Context) (Service, error) {
	ts := &testService{
		ServiceProcessor: NewServiceProcessor(c),
	}
	log.ErrFatal(ts.RegisterHandler(ts.ProcessMsg))
	return ts, nil
}

func (ts *testService) NewProtocol(tn *TreeNodeInstance, conf *GenericConfig) (ProtocolInstance, error) {
	return nil, nil
}

func (ts *testService) ProcessMsg(msg *testMsg) (network.Message, error) {
	ts.Msg = msg
	return msg, nil
}
