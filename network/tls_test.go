package network

import (
	"testing"
	"time"

	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/require"
)

func TestTLS(t *testing.T) {
	log.SetDebugVisible(5)
	type hello struct {
		Hello string
	}
	mt := RegisterMessage(&hello{})

	kp := key.NewKeyPair(tSuite)
	si := NewServerIdentity(kp.Public, NewTLSAddress(":0"))
	si.SetPrivate(kp.Private)

	r, err := NewTCPRouter(si, tSuite)
	require.Nil(t, err, "new tcp router")

	ready := make(chan bool)
	stop := make(chan bool)
	rcv := make(chan bool, 1)

	r.Dispatcher.RegisterProcessorFunc(mt, func(*Envelope) {
		rcv <- true
	})

	go func() {
		ready <- true
		r.Start()
		stop <- true
	}()

	<-ready

	// siClient has remote address set correctly after the OS
	// chose it, and Secret is NOT set.
	siClient := NewServerIdentity(kp.Public, r.address)
	t.Log("sending to", siClient)

	err = r.Send(siClient, &hello{"Hello"})
	require.Nil(t, err, "Could not router.Send")
	<-rcv
	r.Stop()

	select {
	case <-stop:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Could not stop listener")
	}
}
