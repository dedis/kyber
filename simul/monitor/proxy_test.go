package monitor

import (
	"strings"
	"testing"
	"time"
)

func TestProxy(t *testing.T) {
	m := make(map[string]string)
	m["servers"] = "1"
	m["hosts"] = "1"
	m["filter_round"] = "100"
	stat := NewStats(m)
	fresh := stat.String()
	// First set up monitor listening
	monitor := NewMonitor(stat)
	monitor.SinkPort = 0
	done := make(chan bool, 2)
	go func() {
		// See dedis/onet#262 for ideas on a proper fix for all this hard-coding of ports.
		err := monitor.Listen()
		if err != nil {
			panic("monitor.Listen failed")
		}
		done <- true
	}()

	sp := <-monitor.sinkPortChan
	prox, err := NewProxy(sp, "localhost", 0)

	if err != nil {
		t.Fatal("new proxy", err)
	}
	go func() {
		err := prox.Run()
		if err != nil && !strings.Contains(err.Error(), "use of closed") {
			panic("Proxy failed: " + err.Error())
		}
		done <- true
	}()

	time.Sleep(100 * time.Millisecond)
	err = ConnectSink(prox.Listener.Addr().String())
	if err != nil {
		t.Errorf("Can not connect to proxy : %s", err)
		return
	}
	println("here")

	meas := NewTimeMeasure("setup")
	meas.Record()
	time.Sleep(100 * time.Millisecond)
	meas.Record()

	prox.Listener.Close()
	prox.Stop()
	EndAndCleanup()

	select {
	case <-done:
		select {
		case <-done:
			// Second read for checking proxy exited.
			s := monitor.stats
			s.Collect()
			if s.String() == fresh {
				t.Error("stats not updated?")
			}
			return
		case <-time.After(2 * time.Second):
			t.Error("Proxy not finished")
		}
	case <-time.After(2 * time.Second):
		t.Error("Monitor not finished")
	}
}
