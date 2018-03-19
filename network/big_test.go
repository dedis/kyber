package network

import (
	"strconv"
	"sync"
	"testing"

	"gopkg.in/dedis/onet.v2/log"
)

/*
On MacOSX, for maximum number of connections, use
http://b.oldhu.com/2012/07/19/increase-tcp-max-connections-on-mac-os-x/
sudo sysctl -w kern.maxfiles=12288
sudo sysctl -w kern.maxfilesperproc=10240
ulimit -n 10240
sudo sysctl -w kern.ipc.somaxconn=2048
*/

// There seems to be an error if a lot of hosts communicate with each other
// - this function tries to trigger that error so that it can be removed
// It generates one connection between each host and then starts sending
// messages all around.
func TestTCPHugeConnections(t *testing.T) {
	// How many hosts are run
	if testing.Short() {
		t.Skip("Long test - skipping in short mode")
	}
	// How many hosts are run - if you try with nbrHosts >= 15, increase
	// the maximum number of connections using the above snippet.
	nbrHosts := 10
	// 1MB of message size
	msgSize := 1024 * 1024 * 1
	big := bigMessage{
		Msize: msgSize,
		Msg:   make([]byte, msgSize),
		Pcrc:  25,
	}
	bigMessageType := RegisterMessage(big)

	ids := make([]*ServerIdentity, nbrHosts)
	hosts := make([]*TCPListener, nbrHosts)
	// 2-dimensional array of connections between all hosts, where only
	// the upper-right half is populated. The lower-left half is the
	// mirror of the upper-right half, and the diagonal is empty, as there
	// are no connections from one host to itself.
	conns := make([][]Conn, nbrHosts)
	wg := sync.WaitGroup{}
	var err error
	// Create all hosts and open the connections
	for i := 0; i < nbrHosts; i++ {
		addr := NewAddress(PlainTCP, "localhost:"+strconv.Itoa(2000+i))
		ids[i] = NewTestServerIdentity(addr)
		hosts[i], err = NewTCPListener(addr, tSuite)
		if err != nil {
			t.Fatal("Error setting up host:", err)
		}
		log.Lvl5("Host is", hosts[i], "id is", ids[i])
		go func(h int) {
			err := hosts[h].Listen(func(c Conn) {
				log.Lvl5(2000+h, "got a connection")
				nm, err := c.Receive()
				if err != nil {
					t.Fatal("Couldn't receive msg:", err)
				}
				if !nm.MsgType.Equal(bigMessageType) {
					t.Fatal("Received message type is wrong")
				}
				bigCopy := nm.Msg.(*bigMessage)
				if bigCopy.Msize != msgSize {
					t.Fatal(h, "Message-size is wrong:", bigCopy.Msize, bigCopy, big)
				}
				if bigCopy.Pcrc != 25 {
					t.Fatal("CRC is wrong")
				}
				// And send it back
				log.Lvl3(h, "sends it back")

				go func(h int) {
					log.Lvl3(h, "Sending back")
					sentLen, err := c.Send(&big)
					if err != nil {
						t.Fatal(h, "couldn't send message:", err)
					}
					if sentLen == 0 {
						t.Fatal("sentLen is zero")
					}
				}(h)
				log.Lvl3(h, "done sending messages")
			})
			if err != nil {
				t.Fatal("Couldn't receive msg:", err)
			}
		}(i)
		conns[i] = make([]Conn, nbrHosts)
		for j := 0; j < i; j++ {
			wg.Add(1)
			var err error
			log.Lvl5("Connecting", ids[i], "with", ids[j])
			conns[i][j], err = NewTCPConn(ids[j].Address, tSuite)
			if err != nil {
				t.Fatal("Couldn't open:", err)
			}
			// Populate also the lower left for easy sending to
			// everybody
			conns[j][i] = conns[i][j]
		}
	}

	// Start sending messages back and forth
	for i := 0; i < nbrHosts; i++ {
		for j := 0; j < i; j++ {
			c := conns[i][j]
			go func(conn Conn, i, j int) {
				defer wg.Done()
				log.Lvl3("Sending from", i, "to", j, ":")
				sentLen, err := conn.Send(&big)
				if err != nil {
					t.Fatal(i, j, "Couldn't send:", err)
				}
				if sentLen == 0 {
					t.Fatal("sentLen is zero")
				}
				nm, err := conn.Receive()
				if err != nil {
					t.Fatal(i, j, "Couldn't receive:", err)
				}
				bc := nm.Msg.(*bigMessage)
				if bc.Msize != msgSize {
					t.Fatal(i, j, "Message-size is wrong")
				}
				if bc.Pcrc != 25 {
					t.Fatal(i, j, "CRC is wrong")
				}
				log.Lvl3(i, j, "Done")
			}(c, i, j)
		}
	}
	wg.Wait()

	// Close all
	for _, h := range hosts {
		if err := h.Stop(); err != nil {
			t.Fatal("Couldn't close:", err)
		}
	}
}

type bigMessage struct {
	Msize int
	Msg   []byte
	Pcrc  int
}
