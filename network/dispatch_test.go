package network

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type basicProcessor struct {
	envChan chan Envelope
}

func (bp *basicProcessor) Process(env *Envelope) {
	bp.envChan <- *env
}

type basicMessage struct {
	Value int
}

var basicMessageType = RegisterMessage(&basicMessage{})

func TestBlockingDispatcher(t *testing.T) {

	dispatcher := NewBlockingDispatcher()
	processor := &basicProcessor{make(chan Envelope, 1)}

	err := dispatcher.Dispatch(&Envelope{
		Msg:     basicMessage{10},
		MsgType: basicMessageType})

	if err == nil {
		t.Error("Dispatcher should have returned an error")
	}

	dispatcher.RegisterProcessor(processor, basicMessageType)
	dispatcher.Dispatch(&Envelope{
		Msg:     basicMessage{10},
		MsgType: basicMessageType})

	select {
	case m := <-processor.envChan:
		msg, ok := m.Msg.(basicMessage)
		assert.True(t, ok)
		assert.Equal(t, msg.Value, 10)
	default:
		t.Error("No message received")
	}

	var found bool
	dispatcher.RegisterProcessorFunc(basicMessageType, func(e *Envelope) {
		found = true
	})
	dispatcher.Dispatch(&Envelope{
		Msg:     basicMessage{10},
		MsgType: basicMessageType})

	if !found {
		t.Error("ProcessorFunc should have set to true")
	}
}

func TestRoutineDispatcher(t *testing.T) {

	dispatcher := NewRoutineDispatcher()
	if dispatcher == nil {
		t.Fatal("nil dispatcher")
	}
	processor := &basicProcessor{make(chan Envelope, 1)}

	err := dispatcher.Dispatch(&Envelope{
		Msg:     basicMessage{10},
		MsgType: basicMessageType})

	if err == nil {
		t.Error("Dispatcher should have returned an error")
	}

	dispatcher.RegisterProcessor(processor, basicMessageType)
	dispatcher.Dispatch(&Envelope{
		Msg:     basicMessage{10},
		MsgType: basicMessageType})

	select {
	case m := <-processor.envChan:
		msg, ok := m.Msg.(basicMessage)
		assert.True(t, ok)
		assert.Equal(t, msg.Value, 10)
	case <-time.After(100 * time.Millisecond):
		t.Error("No message received")

	}
}

func TestDefaultProcessor(t *testing.T) {
	var okCh = make(chan bool, 1)
	pr := defaultProcessor{func(e *Envelope) {
		okCh <- true
	}}

	pr.Process(&Envelope{})
	select {
	case <-okCh:
	default:
		t.Error("no ack received...")
	}
}
