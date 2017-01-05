// Package monitor package handle the logging, collection and computation of
// statistical data. Every application can send some Measure (for the moment,
// we mostly measure the CPU time but it can be applied later for any kind of
// measures). The Monitor receives them and updates a Stats struct. This Stats
// struct can hold many different kinds of Measurements (the measure of a
// specific action such as "round time" or "verify time" etc). These
// measurements contain Values which compute the actual min/max/dev/avg values.
//
// The Proxy allows to relay Measure from
// clients to the listening Monitor. A starter feature is also the DataFilter
// which can apply some filtering rules to the data before making any
// statistics about them.
package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/dedis/onet/log"
)

// This file handles the collection of measurements, aggregates them and
// write CSV file reports

// Sink is the address where to listen for the monitor. The endpoint can be a
// monitor.Proxy or a direct connection with measure.go
const Sink = "0.0.0.0"

// DefaultSinkPort is the default port where a monitor will listen and a proxy
// will contact the monitor.
const DefaultSinkPort = 10000

// Monitor struct is used to collect measures and make the statistics about
// them. It takes a stats object so it update that in a concurrent-safe manner
// for each new measure it receives.
type Monitor struct {
	listener     net.Listener
	listenerLock *sync.Mutex

	// Current conections
	conns map[string]net.Conn
	// and the mutex to play with it
	mutexConn sync.Mutex

	// Current stats
	stats *Stats
	// and the mutex to play with it
	mutexStats sync.Mutex

	// channel to give new measures
	measures chan *singleMeasure

	// channel to notify the end of a connection
	// send the name of the connection when finishd
	done chan string

	SinkPort int
}

// NewMonitor returns a new monitor given the stats
func NewMonitor(stats *Stats) *Monitor {
	return &Monitor{
		conns:        make(map[string]net.Conn),
		stats:        stats,
		mutexStats:   sync.Mutex{},
		SinkPort:     DefaultSinkPort,
		measures:     make(chan *singleMeasure),
		done:         make(chan string),
		listenerLock: new(sync.Mutex),
	}
}

// Listen will start listening for incoming connections on this address
// It needs the stats struct pointer to update when measures come
// Return an error if something went wrong during the connection setup
func (m *Monitor) Listen() error {
	ln, err := net.Listen("tcp", Sink+":"+strconv.Itoa(m.SinkPort))
	if err != nil {
		return fmt.Errorf("Error while monitor is binding address: %v", err)
	}
	m.listenerLock.Lock()
	m.listener = ln
	m.listenerLock.Unlock()
	log.Lvl2("Monitor listening for stats on", Sink, ":", m.SinkPort)
	finished := false
	go func() {
		for {
			if finished {
				break
			}
			conn, err := ln.Accept()
			if err != nil {
				operr, ok := err.(*net.OpError)
				// We cant accept anymore we closed the listener
				if ok && operr.Op == "accept" {
					break
				}
				log.Lvl2("Error while monitor accept connection:", operr)
				continue
			}
			log.Lvl3("Monitor: new connection from", conn.RemoteAddr().String())
			m.mutexConn.Lock()
			m.conns[conn.RemoteAddr().String()] = conn
			go m.handleConnection(conn)
			m.mutexConn.Unlock()
		}
	}()
	for !finished {
		select {
		// new stats
		case measure := <-m.measures:
			m.update(measure)
		// end of a peer conn
		case peer := <-m.done:
			m.mutexConn.Lock()
			log.Lvl3("Connections left:", len(m.conns))
			delete(m.conns, peer)
			// end of monitoring,
			if len(m.conns) == 0 {
				m.listenerLock.Lock()
				if err := m.listener.Close(); err != nil {
					log.Warn("Couldn't close listener:",
						err)
				}
				m.listener = nil
				finished = true
				m.listenerLock.Unlock()
			}
			m.mutexConn.Unlock()
		}
	}
	log.Lvl2("Monitor finished waiting")
	m.mutexConn.Lock()
	m.conns = make(map[string]net.Conn)
	m.mutexConn.Unlock()
	return nil
}

// Stop will close every connections it has
// And will stop updating the stats
func (m *Monitor) Stop() {
	log.Lvl2("Monitor Stop")
	m.listenerLock.Lock()
	if m.listener != nil {
		if err := m.listener.Close(); err != nil {
			log.Error("Couldn't close listener:", err)
		}
	}
	m.listenerLock.Unlock()
	m.mutexConn.Lock()
	for _, c := range m.conns {
		if err := c.Close(); err != nil {
			log.Error("Couldn't close connection:", err)
		}
	}
	m.mutexConn.Unlock()

}

// handleConnection will decode the data received and aggregates it into its
// stats
func (m *Monitor) handleConnection(conn net.Conn) {
	dec := json.NewDecoder(conn)
	nerr := 0
	for {
		measure := &singleMeasure{}
		if err := dec.Decode(measure); err != nil {
			// if end of connection
			if err == io.EOF || strings.Contains(err.Error(), "closed") {
				break
			}
			// otherwise log it
			log.Lvl2("Error: monitor decoding from", conn.RemoteAddr().String(), ":", err)
			nerr++
			if nerr > 1 {
				log.Lvl2("Monitor: too many errors from", conn.RemoteAddr().String(), ": Abort.")
				break
			}
		}

		log.Lvlf3("Monitor: received a Measure from %s: %+v", conn.RemoteAddr().String(), measure)
		// Special case where the measurement is indicating a FINISHED step
		switch strings.ToLower(measure.Name) {
		case "end":
			log.Lvl3("Finishing monitor")
			m.done <- conn.RemoteAddr().String()
		default:
			m.measures <- measure
		}
	}
}

// updateMeasures will add that specific measure to the global stats
// in a concurrently safe manner
func (m *Monitor) update(meas *singleMeasure) {
	m.mutexStats.Lock()
	// updating
	m.stats.Update(meas)
	m.mutexStats.Unlock()
}

// Stats returns the updated stats in a concurrent-safe manner
func (m *Monitor) Stats() *Stats {
	m.mutexStats.Lock()
	s := m.stats
	m.mutexStats.Unlock()
	return s
}
