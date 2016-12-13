package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/dedis/onet/log"
)

// Implements a simple proxy
// A <-> D <-> B
// D is the proxy. It will listen for incoming connections on the side of B
// And will connect to A

// serverConn is the connection object to the server
var serverConn net.Conn

// to write back the measure to the server
var serverEnc *json.Encoder
var serverDec *json.Decoder
var readyCount int64

// proxy connections opened
var proxyConns map[string]*json.Encoder

var proxyDone chan bool

func init() {
	proxyDone = make(chan bool)
}

// Proxy will launch a routine that waits for input connections
// It takes a redirection address soas to where redirect incoming packets
// Proxy will listen on Sink:SinkPort variables so that the user do not
// differentiate between connecting to a proxy or directly to the sink
// It will panic if it can not contact the server or can not bind to the address
func Proxy(redirection string) error {
	// Connect to the sink

	if err := connectToSink(redirection); err != nil {
		return err
	}
	log.Lvl2("Proxy connected to sink", redirection)

	// The proxy listens on the port one lower than itself
	_, port, err := net.SplitHostPort(redirection)
	if err != nil {
		log.Fatal("Couldn't get port-numbre from", redirection)
	}
	portNbr, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal("Couldn't convert", port, "to a number")
	}
	sinkAddr := Sink + ":" + strconv.Itoa(portNbr-1)
	ln, err := net.Listen("tcp", sinkAddr)
	if err != nil {
		return fmt.Errorf("Error while binding proxy to addr %s: %v", sinkAddr, err)
	}
	log.Lvl2("Proxy listening on", sinkAddr)
	newConn := make(chan bool)
	closeConn := make(chan bool)
	finished := false
	proxyConns := make(map[string]*json.Encoder)

	// Listen for incoming connections
	go func() {
		for finished == false {
			conn, err := ln.Accept()
			if err != nil {
				operr, ok := err.(*net.OpError)
				// the listener is closed
				if ok && operr.Op == "accept" {
					break
				}
				log.Lvl1("Error proxy accepting connection:", err)
				continue
			}
			log.Lvl3("Proxy accepting incoming connection from:", conn.RemoteAddr().String())
			newConn <- true
			proxyConns[conn.RemoteAddr().String()] = json.NewEncoder(conn)
			go proxyConnection(conn, closeConn)
		}
	}()

	go func() {
		// notify every new connection and every end of connection. When all
		// connections are closed, send an "end" measure to the sink.
		var nconn int
		for finished == false {
			select {
			case <-newConn:
				nconn++
			case <-closeConn:
				nconn--
				if nconn == 0 {
					// everything is finished
					if err := serverEnc.Encode(newSingleMeasure("end", 0)); err != nil {
						log.Error("Couldn't send 'end' message:", err)
					}
					if err := serverConn.Close(); err != nil {
						log.Error("Couldn't close server connection:", err)
					}
					if err := ln.Close(); err != nil {
						log.Error("Couldn't close listener:", err)
					}
					finished = true
					break
				}
			}
		}
	}()
	return nil
}

// connectToSink starts the connection with the server
func connectToSink(redirection string) error {
	conn, err := net.Dial("tcp", redirection)
	if err != nil {
		return fmt.Errorf("Proxy connection to server %s failed: %v", redirection, err)
	}
	serverConn = conn
	serverEnc = json.NewEncoder(conn)
	serverDec = json.NewDecoder(conn)
	return nil
}

// The core of the file: read any input from the connection and outputs it into
// the server connection
func proxyConnection(conn net.Conn, done chan bool) {
	dec := json.NewDecoder(conn)
	nerr := 0
	for {
		m := singleMeasure{}
		// Receive data
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			log.Lvl1("Error receiving data from", conn.RemoteAddr().String(), ":", err)
			nerr++
			if nerr > 1 {
				log.Lvl1("Too many errors from", conn.RemoteAddr().String(), ": Abort connection")
				break
			}
		}
		log.Lvl3("Proxy received", m)

		// Proxy data back to monitor
		if err := serverEnc.Encode(m); err != nil {
			log.Lvl2("Error proxying data :", err)
			break
		}
		if m.Name == "end" {
			// the end
			log.Lvl2("Proxy detected end of measurement. Closing connection.")
			break
		}
	}
	if err := conn.Close(); err != nil {
		log.Error("Couldn't close connection:", err)
	}
	done <- true
}

// proxyDataServer send the data to the server...
func proxyDataServer(data []byte) {
	_, err := serverConn.Write(data)
	if err != nil {
		panic(fmt.Errorf("Error proxying data to server: %v", err))
	}
}
