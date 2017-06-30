package onet

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"time"

	"reflect"
	"strings"

	"sync"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/protobuf"
	"github.com/gorilla/websocket"
	"gopkg.in/tylerb/graceful.v1"
)

// WebSocket handles incoming client-requests using the websocket
// protocol. When making a new WebSocket, it will listen one port above the
// ServerIdentity-port-#.
// The websocket protocol has been chosen as smallest common denominator
// for languages including JavaScript.
type WebSocket struct {
	services  map[string]Service
	server    *graceful.Server
	mux       *http.ServeMux
	startstop chan bool
	started   bool
	sync.Mutex
}

const (
	// WebSocketErrorPathNotFound indicates the path has not been registered
	WebSocketErrorPathNotFound = 4000 + iota
	// WebSocketErrorProtobufDecode indicates an error in decoding the protobuf-packet
	WebSocketErrorProtobufDecode
	// WebSocketErrorProtobufEncode indicates an error in encoding the return packet
	WebSocketErrorProtobufEncode
	// WebSocketErrorInvalidErrorCode indicates the service returned
	// an invalid error-code
	WebSocketErrorInvalidErrorCode
	// WebSocketErrorRead indicates that there has been a problem on reception
	WebSocketErrorRead
)

// NewWebSocket opens a webservice-listener one port above the given
// ServerIdentity.
func NewWebSocket(si *network.ServerIdentity) *WebSocket {
	w := &WebSocket{
		services:  make(map[string]Service),
		startstop: make(chan bool),
	}
	webHost, err := getWebAddress(si, true)
	log.ErrFatal(err)
	w.mux = http.NewServeMux()
	w.server = &graceful.Server{
		Timeout: 100 * time.Millisecond,
		Server: &http.Server{
			Addr:    webHost,
			Handler: w.mux,
		},
		NoSignalHandling: true,
	}
	return w
}

// start listening on the port.
func (w *WebSocket) start() {
	w.Lock()
	w.started = true
	w.Unlock()
	log.Lvl3("Starting to listen on", w.server.Server.Addr)
	go func() {
		w.server.ListenAndServe()
	}()
	w.startstop <- true
}

// registerService stores a service to the given path. All requests to that
// path and it's sub-endpoints will be forwarded to ProcessClientRequest.
func (w *WebSocket) registerService(service string, s Service) error {
	w.services[service] = s
	h := &wsHandler{
		service:     s,
		serviceName: service,
	}
	w.mux.Handle(fmt.Sprintf("/%s/", service), h)
	return nil
}

// stop the websocket and free the port.
func (w *WebSocket) stop() {
	w.Lock()
	defer w.Unlock()
	if !w.started {
		return
	}
	log.Lvl3("Stopping", w.server.Server.Addr)
	w.server.Stop(100 * time.Millisecond)
	<-w.startstop
	w.started = false
}

// Pass the request to the websocket.
type wsHandler struct {
	serviceName string
	service     Service
}

// Wrapper-function so that http.Requests get 'upgraded' to websockets
// and handled correctly.
func (t wsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u := websocket.Upgrader{
		EnableCompression: true,
		// As the website will not be served from ourselves, we
		// need to accept _all_ origins. Cross-site scriptiong is
		// required.
		CheckOrigin: func(*http.Request) bool {
			return true
		},
	}
	ws, err := u.Upgrade(w, r, http.Header{})
	if err != nil {
		log.Error(err)
		return
	}
	defer func() {
		ws.Close()
	}()
	var ce ClientError
	// Loop as long as we don't return an error.
	for ce == nil {
		mt, buf, err := ws.ReadMessage()
		if err != nil {
			ce = NewClientErrorCode(WebSocketErrorRead, err.Error())
			return
		}
		s := t.service
		var reply []byte
		path := strings.TrimPrefix(r.URL.Path, "/"+t.serviceName+"/")
		log.Lvl3("Got request for", t.serviceName, path)
		reply, ce = s.ProcessClientRequest(path, buf)
		if ce == nil {
			err := ws.WriteMessage(mt, reply)
			if err != nil {
				log.Error(err)
				return
			}
		}
	}
	if ce.ErrorCode() < 4000 || ce.ErrorCode() >= 5000 {
		ce = NewClientErrorCode(WebSocketErrorInvalidErrorCode, ce.Error())
	}
	ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(ce.ErrorCode(), ce.ErrorMsg()),
		time.Now().Add(time.Millisecond*500))
}

type destination struct {
	si   *network.ServerIdentity
	path string
}

// Client is a struct used to communicate with a remote Service running on a
// onet.Server. Using Send it can connect to multiple remote Servers.
type Client struct {
	service     string
	connections map[destination]*websocket.Conn
	// whether to keep the connection
	keep bool
	rx   uint64
	tx   uint64
	sync.Mutex
}

// NewClient returns a client using the service s. On the first Send, the
// connection will be started, until Close is called.
func NewClient(s string) *Client {
	return &Client{
		service:     s,
		connections: make(map[destination]*websocket.Conn),
	}
}

// NewClientKeep returns a Client that doesn't close the connection between
// two messages if it's the same server.
func NewClientKeep(s string) *Client {
	return &Client{
		service:     s,
		keep:        true,
		connections: make(map[destination]*websocket.Conn),
	}
}

// Send will marshal the message into a ClientRequest message and send it.
func (c *Client) Send(dst *network.ServerIdentity, path string, buf []byte) ([]byte, ClientError) {
	c.Lock()
	defer c.Unlock()
	dest := destination{dst, path}
	conn, ok := c.connections[dest]
	if !ok {
		// Open connection to service.
		url, err := getWebAddress(dst, false)
		if err != nil {
			return nil, NewClientError(err)
		}
		log.Lvlf4("Sending %x to %s/%s/%s", buf, url, c.service, path)
		d := &websocket.Dialer{}
		// Re-try to connect in case the websocket is just about to start
		for a := 0; a < network.MaxRetryConnect; a++ {
			conn, _, err = d.Dial(fmt.Sprintf("ws://%s/%s/%s", url, c.service, path),
				http.Header{"Origin": []string{"http://" + url}})
			if err == nil {
				break
			}
			time.Sleep(network.WaitRetry)
		}
		if err != nil {
			return nil, NewClientError(err)
		}
		c.connections[dest] = conn
	}
	defer func() {
		if !c.keep {
			if err := c.closeConn(dest); err != nil {
				log.Errorf("error while closing the connection to %v : %v\n", dest, err)
			}
		}
	}()
	if err := conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
		return nil, NewClientError(err)
	}
	c.tx += uint64(len(buf))
	_, rcv, err := conn.ReadMessage()
	if err != nil {
		return nil, NewClientError(err)
	}
	log.Lvlf4("Received %x", rcv)
	c.rx += uint64(len(rcv))
	return rcv, nil
}

// SendProtobuf wraps protobuf.(En|De)code over the Client.Send-function. It
// takes the destination, a pointer to a msg-structure that will be
// protobuf-encoded and sent over the websocket. If ret is non-nil, it
// has to be a pointer to the struct that is sent back to the
// client. If there is no error, the ret-structure is filled with the
// data from the service. ClientError has a code and a msg in case
// something went wrong.
func (c *Client) SendProtobuf(dst *network.ServerIdentity, msg interface{}, ret interface{}) ClientError {
	buf, err := protobuf.Encode(msg)
	if err != nil {
		return NewClientError(err)
	}
	path := strings.Split(reflect.TypeOf(msg).String(), ".")[1]
	reply, cerr := c.Send(dst, path, buf)
	if cerr != nil {
		return NewClientError(cerr)
	}
	if ret != nil {
		err := protobuf.DecodeWithConstructors(reply, ret,
			network.DefaultConstructors(network.Suite))
		return NewClientError(err)
	}
	return nil
}

// SendToAll sends a message to all ServerIdentities of the Roster and returns
// all errors encountered concatenated together as a string.
func (c *Client) SendToAll(dst *Roster, path string, buf []byte) ([][]byte, ClientError) {
	msgs := make([][]byte, len(dst.List))
	var errstrs []string
	for i, e := range dst.List {
		var err ClientError
		msgs[i], err = c.Send(e, path, buf)
		if err != nil {
			errstrs = append(errstrs, fmt.Sprint(e.String(), err.Error()))
		}
	}
	var err error
	if len(errstrs) > 0 {
		err = errors.New(strings.Join(errstrs, "\n"))
	}
	return msgs, NewClientError(err)
}

// Close sends a close-command to all open connections and returns nil if no
// errors occurred or all errors encountered concatenated together as a string.
func (c *Client) Close() error {
	c.Lock()
	defer c.Unlock()
	var errstrs []string
	for dest := range c.connections {
		if err := c.closeConn(dest); err != nil {
			errstrs = append(errstrs, err.Error())
		}
	}
	var err error
	if len(errstrs) > 0 {
		err = errors.New(strings.Join(errstrs, "\n"))
	}
	return err
}

// closeConn sends a close-command to the connection.
func (c *Client) closeConn(dst destination) error {
	conn, ok := c.connections[dst]
	if ok {
		delete(c.connections, dst)
		conn.WriteMessage(websocket.CloseMessage, nil)
		return conn.Close()
	}
	return nil
}

// Tx returns the number of bytes transmitted by this Client. It implements
// the monitor.CounterIOMeasure interface.
func (c *Client) Tx() uint64 {
	c.Lock()
	defer c.Unlock()
	return c.tx
}

// Rx returns the number of bytes read by this Client. It implements
// the monitor.CounterIOMeasure interface.
func (c *Client) Rx() uint64 {
	c.Lock()
	defer c.Unlock()
	return c.rx
}

// ClientError allows for returning error-codes and error-messages. It is
// implemented by cerror, that can be instantiated using NewClientError and
// NewClientErrorCode.
type ClientError interface {
	Error() string
	ErrorCode() int
	ErrorMsg() string
}

type cerror struct {
	code int
	msg  string
}

const wsPrefix = "websocket: close "

// NewClientError takes a standard error and
// - returns a ClientError if it's a standard error
// or
// - parses the wsPrefix to correctly get the id and msg of the error
func NewClientError(e error) ClientError {
	if e == nil {
		return nil
	}
	str := e.Error()
	if strings.HasPrefix(str, wsPrefix) {
		str = str[len(wsPrefix):]
		errMsg := strings.Split(str, ":")
		if len(errMsg) > 1 && len(errMsg[1]) > 0 {
			errMsg[1] = errMsg[1][1:]
		} else {
			errMsg = append(errMsg, "")
		}
		errCode, _ := strconv.Atoi(errMsg[0])
		return &cerror{errCode, errMsg[1]}
	}
	return &cerror{0, e.Error()}
}

// NewClientErrorCode takes an errorCode and an errorMsg and returns the
// corresponding ClientError.
func NewClientErrorCode(code int, msg string) ClientError {
	return &cerror{code, msg}
}

// ErrorCode returns the errorCode.
func (ce *cerror) ErrorCode() int {
	return ce.code
}

// ErrorMsg returns the errorMsg.
func (ce *cerror) ErrorMsg() string {
	return ce.msg
}

// Error makes the cerror-structure confirm to the error-interface.
func (ce *cerror) Error() string {
	if ce == nil {
		return ""
	}
	if ce.code > 0 {
		return fmt.Sprintf(wsPrefix+"%d: %s", ce.code, ce.msg)
	}
	return ce.msg
}

// getWebAddress returns the host:port+1 of the serverIdentity. If
// global is true, the address is set to the unspecified 0.0.0.0-address.
func getWebAddress(si *network.ServerIdentity, global bool) (string, error) {
	p, err := strconv.Atoi(si.Address.Port())
	if err != nil {
		return "", err
	}
	host := si.Address.Host()
	if global {
		host = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", host, p+1), nil
}
