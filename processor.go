package onet

import (
	"errors"
	"reflect"

	"strings"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/protobuf"
)

// ServiceProcessor allows for an easy integration of external messages
// into the Services. You have to embed it into your Service-struct as
// a pointer. It will process client requests that have been registered
// with RegisterMessage.
type ServiceProcessor struct {
	handlers map[string]serviceHandler
	*Context
}

// serviceHandler stores the handler and the message-type.
type serviceHandler struct {
	handler interface{}
	msgType reflect.Type
}

// NewServiceProcessor initializes your ServiceProcessor.
func NewServiceProcessor(c *Context) *ServiceProcessor {
	return &ServiceProcessor{
		handlers: make(map[string]serviceHandler),
		Context:  c,
	}
}

// RegisterHandler will store the given handler that will be used by the service.
// WebSocket will then forward requests to "ws://service_name/struct_name"
// to the given function f, which must be of the following form:
// func(msg interface{})(ret interface{}, err ClientError)
//
//  * msg is a pointer to a structure to the message sent.
//  * ret is a pointer to a struct of the return-message.
//  * err is a Client-error and can return nil or a ClientError that holds
//	an error-id and an error-msg.
//
// struct_name is stripped of its package-name, so a structure like
// network.Body will be converted to Body.
func (p *ServiceProcessor) RegisterHandler(f interface{}) error {
	ft := reflect.TypeOf(f)
	// Check that we have the correct channel-type.
	if ft.Kind() != reflect.Func {
		return errors.New("Input is not a function")
	}
	if ft.NumIn() != 1 {
		return errors.New("Need one argument: *struct")
	}
	cr := ft.In(0)
	if cr.Kind() != reflect.Ptr {
		return errors.New("Argument must be a *pointer* to a struct")
	}
	if cr.Elem().Kind() != reflect.Struct {
		return errors.New("Argument must be a pointer to *struct*")
	}
	if ft.NumOut() != 2 {
		return errors.New("Need 2 return values: network.Body and ClientError")
	}

	ret := ft.Out(0)
	if ret.Kind() != reflect.Interface {
		if ret.Kind() != reflect.Ptr {
			return errors.New("1st return value must be a *pointer* to a struct or an interface")
		}
		if ret.Elem().Kind() != reflect.Struct {
			return errors.New("1st return value must be a pointer to a *struct* or an interface")
		}
	}

	if ft.Out(1) != reflect.TypeOf((*ClientError)(nil)).Elem() {
		return errors.New("2nd return value has to be: ClientError, but is: " +
			ft.Out(1).String())
	}

	log.Lvl4("Registering handler", cr.String())
	pm := strings.Split(cr.Elem().String(), ".")[1]
	p.handlers[pm] = serviceHandler{f, cr.Elem()}
	return nil
}

// RegisterHandlers takes a vararg of messages to register and returns
// the first error encountered or nil if everything was OK.
func (p *ServiceProcessor) RegisterHandlers(procs ...interface{}) error {
	for _, pr := range procs {
		if err := p.RegisterHandler(pr); err != nil {
			return err
		}
	}
	return nil
}

// Process implements the Processor interface and dispatches ClientRequest messages.
func (p *ServiceProcessor) Process(env *network.Envelope) {
	log.Panic("Cannot handle message.")
}

// NewProtocol is a stub for services that don't want to intervene in the
// protocol-handling.
func (p *ServiceProcessor) NewProtocol(tn *TreeNodeInstance, conf *GenericConfig) (ProtocolInstance, error) {
	return nil, nil
}

// ProcessClientRequest takes a request from a client, calculates the reply
// and sends it back. It uses the path to find the appropriate handler-
// function. It implements the Server interface.
func (p *ServiceProcessor) ProcessClientRequest(path string, buf []byte) ([]byte, ClientError) {
	mh, ok := p.handlers[path]
	reply, cerr := func() (interface{}, ClientError) {
		if !ok {
			return nil, NewClientErrorCode(WebSocketErrorPathNotFound, "Path not found")
		}
		msg := reflect.New(mh.msgType).Interface()
		err := protobuf.DecodeWithConstructors(buf, msg,
			network.DefaultConstructors(network.Suite))
		if err != nil {
			return nil, NewClientErrorCode(WebSocketErrorProtobufDecode, err.Error())
		}

		to := reflect.TypeOf(mh.handler).In(0)
		f := reflect.ValueOf(mh.handler)

		arg := reflect.New(to.Elem())
		arg.Elem().Set(reflect.ValueOf(msg).Elem())
		ret := f.Call([]reflect.Value{arg})

		cerr := ret[1].Interface()

		if cerr != nil {
			return nil, cerr.(ClientError)
		}
		return ret[0].Interface(), nil
	}()
	if cerr != nil {
		return nil, cerr
	}
	buf, err := protobuf.Encode(reply)
	if err != nil {
		log.Error(err)
		return nil, NewClientErrorCode(WebSocketErrorProtobufEncode, "")
	}
	return buf, nil
}
