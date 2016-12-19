package network

import (
	"sync"
	"testing"
	"time"

	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func NewTestRouterTCP(port int) (*Router, error) {
	h, err := NewTestTCPHost(port)
	if err != nil {
		return nil, err
	}
	id := NewTestServerIdentity(h.addr)
	return NewRouter(id, h), nil
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

func testRouterRemoveConnection(t *testing.T) {
	r1, err := NewTestRouterTCP(2008)
	require.Nil(t, err)
	r2, err := NewTestRouterTCP(2009)
	require.Nil(t, err)

	defer r1.Stop()

	go r1.Start()
	go r2.Start()

	require.NotNil(t, r1.Send(r2.ServerIdentity, nil))

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
	err = h1.Send(&ServerIdentity{Address: NewLocalAddress("127.1.2.3:2890")}, &SimpleMessage{12})
	if err == nil {
		t.Fatal("Should not be able to send")
	}
	h2, err := fac(2008)
	if err != nil {
		t.Fatal(err)
	}

	err = h1.Send(h2.ServerIdentity, nil)
	require.NotNil(t, err)

	go h2.Start()
	for !h2.Listening() {
		time.Sleep(10 * time.Millisecond)
	}

	clean := func() {
		assert.Nil(t, h1.Stop())
		assert.Nil(t, h2.Stop())
	}
	defer clean()

	proc := newSimpleMessageProc(t)
	h2.RegisterProcessor(proc, SimpleMessageType)
	h1.RegisterProcessor(proc, SimpleMessageType)

	err = h1.Send(h2.ServerIdentity, &SimpleMessage{12})
	require.Nil(t, err)

	// Receive the message
	msg := <-proc.relay
	if msg.I != 12 {
		t.Fatal("Simple message got distorted")
	}

	h12 := h1.connection(h2.ServerIdentity.ID)
	h21 := h2.connection(h1.ServerIdentity.ID)
	assert.NotNil(t, h12)
	require.NotNil(t, h21)
	assert.Nil(t, h21.Close())
	time.Sleep(100 * time.Millisecond)
	err = h1.Send(h2.ServerIdentity, &SimpleMessage{12})
	require.Nil(t, err)
	<-proc.relay

	if err := h2.Stop(); err != nil {
		t.Fatal("Should be able to stop h2")
	}
	err = h1.Send(h2.ServerIdentity, &SimpleMessage{12})
	require.NotNil(t, err)

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
	err := h1.Send(h2.ServerIdentity, msgSimple)
	require.Nil(t, err)
	decoded := <-proc.relay
	assert.Equal(t, 3, decoded.I)

	// make sure the connection is registered in host1 (because it's launched in
	// a go routine). Since we try to avoid random timeout, let's send a msg
	// from host2 -> host1.
	assert.Nil(t, h2.Send(h1.ServerIdentity, msgSimple))
	decoded = <-proc.relay
	assert.Equal(t, 3, decoded.I)

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

func (p *nSquareProc) Process(pack *Packet) {
	p.Lock()
	defer p.Unlock()
	remote := pack.ServerIdentity.Address
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
	if err := p.r.Send(pack.ServerIdentity, &SimpleMessage{3}); err != nil {
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
				if err := r.Send(routers[k].ServerIdentity, &SimpleMessage{3}); err != nil {
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

	msgSimple := &SimpleMessage{5}
	err := h1.Send(h2.ServerIdentity, msgSimple)
	if err != nil {
		t.Fatal("Couldn't send message from h1 to h2", err)
	}
	msg := <-proc.relay
	log.Lvl2("Received msg h1 -> h2", msg)

	err = h2.Send(h1.ServerIdentity, msgSimple)
	if err != nil {
		t.Fatal("Couldn't send message from h2 to h1", err)
	}
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
	c, err := NewTCPConn(router1.ServerIdentity.Address)
	if err != nil {
		t.Fatal("Couldn't connect to host1:", err)
	}
	if err := c.Send(router2.ServerIdentity); err != nil {
		t.Fatal("Wrong negotiation")
	}
	// triggers the dispatching conditional branch error router.go:
	//  `log.Lvl3("Error dispatching:", err)`
	if err := router2.Send(router1.ServerIdentity, &SimpleMessage{12}); err != nil {
		t.Fatal("Could not send")
	}
	c.Close()

	// try messing with the connections here
	c, err = NewTCPConn(router1.ServerIdentity.Address)
	if err != nil {
		t.Fatal("Couldn't connect to host1:", err)
	}
	// closing before sending
	c.Close()
	if err := c.Send(router2.ServerIdentity); err == nil {
		t.Fatal("negotiation should have aborted")
	}

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
