package network

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/kyber.v2/util/key"
)

func NewTestTLSHost(port int) (*TCPHost, error) {
	addr := NewTLSAddress("127.0.0.1:" + strconv.Itoa(port))
	kp := key.NewKeyPair(tSuite)
	e := NewServerIdentity(kp.Public, addr)
	e.SetPrivate(kp.Private)
	return NewTCPHost(e, tSuite)
}

func NewTestRouterTLS(port int) (*Router, error) {
	h, err := NewTestTLSHost(port)
	if err != nil {
		return nil, err
	}
	h.sid.Address = h.TCPListener.Address()
	r := NewRouter(h.sid, h)
	return r, nil
}

type hello struct {
	Hello string
	From  ServerIdentity
}

var aKey = key.NewKeyPair(tSuite)
var aHello = &hello{
	Hello: "Howdy, partner.",
	From:  *NewServerIdentity(aKey.Public, "127.0.0.1:9999"),
}

func TestTLS(t *testing.T) {
	r1, err := NewTestRouterTLS(0)
	require.Nil(t, err, "new tcp router")
	r2, err := NewTestRouterTLS(0)
	require.Nil(t, err, "new tcp router 2")

	ready := make(chan bool)
	stop := make(chan bool)
	rcv := make(chan bool, 1)

	mt := RegisterMessage(&hello{})
	r1.Dispatcher.RegisterProcessorFunc(mt, func(*Envelope) {
		rcv <- true
	})

	go func() {
		ready <- true
		r1.Start()
		stop <- true
	}()
	go func() {
		ready <- true
		r2.Start()
		stop <- true
	}()

	<-ready
	<-ready

	// We want these cleanups to happen if we leave by the require failing
	// or by the end of the function.
	defer func() {
		r1.Stop()
		r2.Stop()

		for i := 0; i < 2; i++ {
			select {
			case <-stop:
			case <-time.After(100 * time.Millisecond):
				t.Fatal("Could not stop router", i)
			}
		}
	}()

	// now send a message from r2 to r1
	sentLen, err := r2.Send(r1.ServerIdentity, aHello)
	require.Nil(t, err, "Could not router.Send")
	require.NotZero(t, sentLen)

	<-rcv
}

func BenchmarkMsgTCP(b *testing.B) {
	r1, err := NewTestRouterTCP(0)
	require.Nil(b, err, "new tcp router")
	r2, err := NewTestRouterTCP(0)
	require.Nil(b, err, "new tcp router 2")
	benchmarkMsg(b, r1, r2)
}

func BenchmarkMsgTLS(b *testing.B) {
	r1, err := NewTestRouterTLS(0)
	require.Nil(b, err, "new tls router")
	r2, err := NewTestRouterTLS(0)
	require.Nil(b, err, "new tls router 2")
	benchmarkMsg(b, r1, r2)
}

func benchmarkMsg(b *testing.B, r1, r2 *Router) {
	mt := RegisterMessage(&hello{})
	r1.Dispatcher.RegisterProcessorFunc(mt, func(*Envelope) {
		// Don't do anything. We are not interested in
		// benchmarking this work.
	})

	ready := make(chan bool)
	stop := make(chan bool)

	go func() {
		ready <- true
		r1.Start()
		stop <- true
	}()
	go func() {
		ready <- true
		r2.Start()
		stop <- true
	}()

	<-ready
	<-ready

	// Setup is complete.
	b.ReportAllocs()
	b.ResetTimer()

	// Send one message from r2 to r1.
	for i := 0; i < b.N; i++ {
		_, err := r2.Send(r1.ServerIdentity, aHello)
		if err != nil {
			b.Log("Could not router.Send")
		}
	}

	r1.Stop()
	r2.Stop()

	for i := 0; i < 2; i++ {
		select {
		case <-stop:
		case <-time.After(100 * time.Millisecond):
			b.Fatal("Could not stop router", i)
		}
	}
}
