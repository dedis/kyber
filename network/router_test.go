package network

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v2/log"
)

func NewTestRouterTCP(port int) (*Router, error) {
	h, err := NewTestTCPHost(port)
	if err != nil {
		return nil, err
	}
	h.sid.Address = h.TCPListener.Address()
	r := NewRouter(h.sid, h)
	r.UnauthOk = true
	return r, nil
}

func NewTestRouterLocal(port int) (*Router, error) {
	h, err := NewTestLocalHost(port)
	if err != nil {
		return nil, err
	}
	id := NewTestServerIdentity(h.addr)
	return NewRouter(id, h), nil
}

type routerFactory func(port int) (*Router, error)

// Test if router fits the interface such as calling Run(), then Stop(),
// should return
func TestRouterTCP(t *testing.T) {
	testRouter(t, NewTestRouterTCP)
}
func TestRouterLocal(t *testing.T) {
	testRouter(t, NewTestRouterLocal)
}

func testRouter(t *testing.T, fac routerFactory) {
	h, err := fac(2004)
	if err != nil {
		t.Fatal(err)
	}
	var stop = make(chan bool)
	go func() {
		stop <- true
		h.Start()
		stop <- true
	}()
	<-stop
	// Time needed so the listener is up. Equivalent to "connecting ourself" as
	// we had before.
	time.Sleep(250 * time.Millisecond)
	h.Stop()
	select {
	case <-stop:
		return
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TcpHost should have returned from Run() by now")
	}
}

// Test connection of multiple Hosts and sending messages back and forth
// also tests for the counterIO interface that it works well
func TestRouterErrorHandling(t *testing.T) {
	h1, err1 := NewTestRouterTCP(2109)
	h2, err2 := NewTestRouterTCP(2110)
	if err1 != nil || err2 != nil {
		t.Fatal("Could not setup hosts")
	}

	go h1.Start()
	go h2.Start()

	defer func() {
		h1.Stop()
	}()

	// tests the setting error handler
	require.NotNil(t, h1.connectionErrorHandlers)
	if len(h1.connectionErrorHandlers) != 0 {
		t.Error("errorHandlers should start empty")
	}
	errHandlerCalled := make(chan bool, 1)
	errHandler := func(remote *ServerIdentity) {
		errHandlerCalled <- true
	}
	h1.AddErrorHandler(errHandler)
	if len(h1.connectionErrorHandlers) != 1 {
		t.Error("errorHandlers should now hold one function")
	}

	//register handlers
	proc := &simpleMessageProc{t, make(chan SimpleMessage)}
	h1.RegisterProcessor(proc, SimpleMessageType)
	h2.RegisterProcessor(proc, SimpleMessageType)

	msgSimple := &SimpleMessage{3}
	sentLen, err := h1.Send(h2.ServerIdentity, msgSimple)
	require.Nil(t, err)
	require.NotZero(t, sentLen)
	decoded := <-proc.relay
	require.Equal(t, 3, decoded.I)
	sentLen, err = h2.Send(h1.ServerIdentity, msgSimple)
	require.Nil(t, err)
	require.NotZero(t, sentLen)
	decoded = <-proc.relay

	//stop node 2
	h2.Stop()

	// test if the error handler was called
	select {
	case <-errHandlerCalled:
		// all good
	case <-time.After(250 * time.Millisecond):
		t.Error("Error handler should have been called after a disconnection")
	}
}
func testRouterRemoveConnection(t *testing.T) {
	r1, err := NewTestRouterTCP(2008)
	require.Nil(t, err)
	r2, err := NewTestRouterTCP(2009)
	require.Nil(t, err)

	defer r1.Stop()

	go r1.Start()
	go r2.Start()

	sentLen, err := r1.Send(r2.ServerIdentity, nil)
	require.NotNil(t, err)
	require.Zero(t, sentLen)

	r1.Lock()
	require.Equal(t, 1, len(r1.connections[r2.ServerIdentity.ID]))
	r1.Unlock()

	require.Nil(t, r2.Stop())

	r1.Lock()
	require.Equal(t, 0, len(r1.connections[r2.ServerIdentity.ID]))
	r1.Unlock()
}

// Test the automatic connection upon request
func TestRouterAutoConnectionTCP(t *testing.T) {
	testRouterAutoConnection(t, NewTestRouterTCP)
}
func TestRouterAutoConnectionLocal(t *testing.T) {
	testRouterAutoConnection(t, NewTestRouterLocal)
}

func testRouterAutoConnection(t *testing.T, fac routerFactory) {
	h1, err := fac(2007)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h1.Send(&ServerIdentity{Address: NewLocalAddress("127.1.2.3:2890")}, &SimpleMessage{12})
	require.NotNil(t, err, "Should not be able to send")

	h2, err := fac(2008)
	if err != nil {
		t.Fatal(err)
	}

	_, err = h1.Send(h2.ServerIdentity, nil)
	require.NotNil(t, err)

	go h2.Start()
	for !h2.Listening() {
		time.Sleep(10 * time.Millisecond)
	}

	clean := func() {
		require.Nil(t, h1.Stop())
		require.Nil(t, h2.Stop())
	}
	defer clean()

	proc := newSimpleMessageProc(t)
	h2.RegisterProcessor(proc, SimpleMessageType)
	h1.RegisterProcessor(proc, SimpleMessageType)

	sentLen, err := h1.Send(h2.ServerIdentity, &SimpleMessage{12})
	require.Nil(t, err)
	require.NotZero(t, sentLen)

	// Receive the message
	msg := <-proc.relay
	if msg.I != 12 {
		t.Fatal("Simple message got distorted")
	}

	h12 := h1.connection(h2.ServerIdentity.ID)
	h21 := h2.connection(h1.ServerIdentity.ID)
	require.NotNil(t, h12)
	require.NotNil(t, h21)
	require.Nil(t, h21.Close())
	time.Sleep(100 * time.Millisecond)

	sentLen, err = h1.Send(h2.ServerIdentity, &SimpleMessage{12})
	require.Nil(t, err)
	require.NotZero(t, sentLen)
	<-proc.relay

	if err := h2.Stop(); err != nil {
		t.Fatal("Should be able to stop h2")
	}
	_, err = h1.Send(h2.ServerIdentity, &SimpleMessage{12})
	if err == nil {
		// This should not happen, but it can due to a race in
		// the kernel between closing and writing to the
		// existing h1->h2 TCP connections.  It would be nice
		// to fix this to make the tests more deterministic,
		// but for now we'll just give up and log it.
		t.Log("h1 let us send still")
	}
}

// Test connection of multiple Hosts and sending messages back and forth
// also tests for the counterIO interface that it works well
func TestRouterMessaging(t *testing.T) {
	h1, err1 := NewTestRouterTCP(2009)
	h2, err2 := NewTestRouterTCP(2010)
	if err1 != nil || err2 != nil {
		t.Fatal("Could not setup hosts")
	}

	go h1.Start()
	go h2.Start()

	defer func() {
		h1.Stop()
		h2.Stop()
		time.Sleep(250 * time.Millisecond)
	}()

	proc := &simpleMessageProc{t, make(chan SimpleMessage)}
	h1.RegisterProcessor(proc, SimpleMessageType)
	h2.RegisterProcessor(proc, SimpleMessageType)

	msgSimple := &SimpleMessage{3}
	sentLen, err := h1.Send(h2.ServerIdentity, msgSimple)
	require.Nil(t, err)
	require.NotZero(t, sentLen)

	decoded := <-proc.relay
	require.Equal(t, 3, decoded.I)

	// make sure the connection is registered in host1 (because it's launched in
	// a go routine). Since we try to avoid random timeout, let's send a msg
	// from host2 -> host1.
	sentLen, err = h2.Send(h1.ServerIdentity, msgSimple)
	require.Nil(t, err)
	require.NotZero(t, sentLen)

	decoded = <-proc.relay
	require.Equal(t, 3, decoded.I)

	written := h1.Tx()
	read := h2.Rx()
	if written == 0 || read == 0 || written != read {
		log.Errorf("Tx = %d, Rx = %d", written, read)
		log.Errorf("h1.Tx() %d vs h2.Rx() %d", h1.Tx(), h2.Rx())
		log.Errorf("Something is wrong with Host.CounterIO")
	}
}

func TestRouterLotsOfConnTCP(t *testing.T) {
	testRouterLotsOfConn(t, NewTestRouterTCP, 5)
}

func TestRouterLotsOfConnLocal(t *testing.T) {
	testRouterLotsOfConn(t, NewTestRouterLocal, 5)
}

// nSquareProc will send back all packet sent and stop when it has received
// enough, it releases the waitgroup.
type nSquareProc struct {
	t           *testing.T
	r           *Router
	expected    int
	wg          *sync.WaitGroup
	firstRound  map[Address]bool
	secondRound map[Address]bool
	sync.Mutex
}

func newNSquareProc(t *testing.T, r *Router, expect int, wg *sync.WaitGroup) *nSquareProc {
	return &nSquareProc{t, r, expect, wg, make(map[Address]bool), make(map[Address]bool), sync.Mutex{}}
}

func (p *nSquareProc) Process(env *Envelope) {
	p.Lock()
	defer p.Unlock()
	remote := env.ServerIdentity.Address
	ok := p.firstRound[remote]
	if ok {
		// second round
		if ok := p.secondRound[remote]; ok {
			p.t.Fatal("Already received second round")
		}
		p.secondRound[remote] = true

		if len(p.secondRound) == p.expected {
			// release
			p.wg.Done()
		}
		return
	}

	p.firstRound[remote] = true
	if _, err := p.r.Send(env.ServerIdentity, &SimpleMessage{3}); err != nil {
		p.t.Fatal("Could not send to first round dest.")
	}

}

// Makes a big mesh where every host send and receive to every other hosts
func testRouterLotsOfConn(t *testing.T, fac routerFactory, nbrRouter int) {
	// create all the routers
	routers := make([]*Router, nbrRouter)
	// to wait for the creation of all hosts
	var wg1 sync.WaitGroup
	wg1.Add(nbrRouter)
	var wg2 sync.WaitGroup
	wg2.Add(nbrRouter)
	for i := 0; i < nbrRouter; i++ {
		go func(j int) {
			r, err := fac(2000 + j)
			if err != nil {
				t.Fatal(err)
			}
			go r.Start()
			for !r.Listening() {
				time.Sleep(20 * time.Millisecond)
			}
			routers[j] = r
			// expect nbrRouter - 1 messages
			proc := newNSquareProc(t, r, nbrRouter-1, &wg2)
			r.RegisterProcessor(proc, SimpleMessageType)
			wg1.Done()
		}(i)
	}
	wg1.Wait()

	for i := 0; i < nbrRouter; i++ {
		go func(j int) {
			r := routers[j]
			for k := 0; k < nbrRouter; k++ {
				if k == j {
					// don't send to yourself
					continue
				}
				// send to everyone else
				if _, err := r.Send(routers[k].ServerIdentity, &SimpleMessage{3}); err != nil {
					t.Fatal(err)
				}
			}
		}(i)
	}
	wg2.Wait()
	for i := 0; i < nbrRouter; i++ {
		r := routers[i]
		if err := r.Stop(); err != nil {
			t.Fatal(err)
		}

	}
}

// Test sending data back and forth using the sendProtocolMsg
func TestRouterSendMsgDuplexTCP(t *testing.T) {
	testRouterSendMsgDuplex(t, NewTestRouterTCP)
}

func TestRouterSendMsgDuplexLocal(t *testing.T) {
	testRouterSendMsgDuplex(t, NewTestRouterLocal)
}
func testRouterSendMsgDuplex(t *testing.T, fac routerFactory) {
	h1, err1 := fac(2011)
	h2, err2 := fac(2012)
	if err1 != nil {
		t.Fatal("Could not setup hosts: ", err1)
	}
	if err2 != nil {
		t.Fatal("Could not setup hosts: ", err2)
	}
	go h1.Start()
	go h2.Start()

	defer func() {
		h1.Stop()
		h2.Stop()
		time.Sleep(250 * time.Millisecond)
	}()

	proc := &simpleMessageProc{t, make(chan SimpleMessage)}
	h1.RegisterProcessor(proc, SimpleMessageType)
	h2.RegisterProcessor(proc, SimpleMessageType)

	msgSimple := &SimpleMessage{5}
	sentLen, err := h1.Send(h2.ServerIdentity, msgSimple)
	require.Nil(t, err, "Couldn't send message from h1 to h2")
	require.NotZero(t, sentLen)

	msg := <-proc.relay
	log.Lvl2("Received msg h1 -> h2", msg)

	sentLen, err = h2.Send(h1.ServerIdentity, msgSimple)
	require.Nil(t, err, "Couldn't send message from h2 to h1")
	require.NotZero(t, sentLen)

	msg = <-proc.relay
	log.Lvl2("Received msg h2 -> h1", msg)
}

func TestRouterExchange(t *testing.T) {
	log.OutputToBuf()
	defer log.OutputToOs()
	router1, err := NewTestRouterTCP(7878)
	router2, err2 := NewTestRouterTCP(8787)
	if err != nil || err2 != nil {
		t.Fatal("Could not setup host", err, err2)
	}

	done := make(chan bool)
	go func() {
		done <- true
		router1.Start()
		done <- true
	}()
	<-done
	// try correctly
	c, err := NewTCPConn(router1.ServerIdentity.Address, tSuite)
	if err != nil {
		t.Fatal("Couldn't connect to host1:", err)
	}
	sentLen, err := c.Send(router2.ServerIdentity)
	require.Nil(t, err, "Wrong negotiation")
	require.NotZero(t, sentLen)

	// triggers the dispatching conditional branch error router.go:
	//  `log.Lvl3("Error dispatching:", err)`
	sentLen, err = router2.Send(router1.ServerIdentity, &SimpleMessage{12})
	require.Nil(t, err, "Could not send")
	require.NotZero(t, sentLen)
	c.Close()

	// try messing with the connections here
	c, err = NewTCPConn(router1.ServerIdentity.Address, tSuite)
	if err != nil {
		t.Fatal("Couldn't connect to host1:", err)
	}
	// closing before sending
	c.Close()
	_, err = c.Send(router2.ServerIdentity)
	require.NotNil(t, err, "negotiation should have aborted")

	// stop everything
	log.Lvl4("Closing connections")
	if err := router2.Stop(); err != nil {
		t.Fatal("Couldn't close host", err)
	}
	if err := router1.Stop(); err != nil {
		t.Fatal("Couldn't close host", err)
	}
	<-done
}

func TestRouterRxTx(t *testing.T) {
	router1, err := NewTestRouterTCP(0)
	log.ErrFatal(err)
	router2, err := NewTestRouterTCP(0)
	log.ErrFatal(err)
	go router1.Start()
	go router2.Start()

	addr := NewAddress(router1.address.ConnType(), "127.0.0.1:"+router1.address.Port())
	si1 := NewServerIdentity(Suite.Point(tSuite).Null(), addr)

	sentLen, err := router2.Send(si1, si1)
	require.Nil(t, err)
	require.NotZero(t, sentLen)

	// Wait for the message to be sent and received
	waitTimeout(time.Second, 10, func() bool {
		return router1.Rx() > 0 && router1.Rx() == router2.Tx()
	})
	rx := router1.Rx()
	require.Equal(t, 1, len(router1.connections))
	router1.Lock()
	var si2 ServerIdentityID
	for si2 = range router1.connections {
		log.Lvl3("Connection:", si2)
	}
	router1.Unlock()
	router2.Stop()
	waitTimeout(time.Second, 10, func() bool {
		router1.Lock()
		defer router1.Unlock()
		return len(router1.connections[si2]) == 0
	})
	require.Equal(t, rx, router1.Rx())
	defer router1.Stop()
}

func waitTimeout(timeout time.Duration, repeat int,
	f func() bool) {
	success := make(chan bool)
	go func() {
		for !f() {
			time.Sleep(timeout / time.Duration(repeat))
		}
		success <- true
	}()
	select {
	case <-success:
	case <-time.After(timeout):
		log.Fatal("Timeout" + log.Stack())
	}

}
