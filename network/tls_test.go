package network

import (
	"testing"
	"time"

	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/require"
)

func TestTLS(t *testing.T) {
	log.SetDebugVisible(3)
	type hello struct {
		Hello string
	}
	mt := RegisterMessage(&hello{})

	kp1 := key.NewKeyPair(tSuite)
	sid1 := NewServerIdentity(kp1.Public, NewTLSAddress(":0"))
	sid1.SetPrivate(kp1.Private)

	r1, err := NewTCPRouter(sid1, tSuite)
	require.Nil(t, err, "new tcp router")
	sid1.Address = r1.address

	kp2 := key.NewKeyPair(tSuite)
	sid2 := NewServerIdentity(kp2.Public, NewTLSAddress(":0"))
	sid2.SetPrivate(kp2.Private)

	r2, err := NewTCPRouter(sid2, tSuite)
	require.Nil(t, err, "new tcp router 2")

	ready := make(chan bool)
	stop := make(chan bool)
	rcv := make(chan bool, 1)

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

	// now send a message from r2 to r1
	err = r2.Send(sid1, &hello{"Hello"})
	require.Nil(t, err, "Could not router.Send")

	<-rcv
	r1.Stop()
	r2.Stop()

	for i := 0; i < 2; i++ {
		select {
		case <-stop:
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Could not stop router", i)
		}
	}
}
