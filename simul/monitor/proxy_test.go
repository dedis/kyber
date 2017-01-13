package monitor

import (
	"strconv"
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
	monitor.SinkPort = 8000
	done := make(chan bool)
	go func() {
		monitor.Listen()
		done <- true
	}()
	time.Sleep(100 * time.Millisecond)
	// Then setup proxy
	// change port so the proxy does not listen to the same
	// than the original monitor

	// proxy listens to 0.0.0.0:8000 & redirects to
	// localhost:10000 (DefaultSinkPort)
	go Proxy("localhost:" + strconv.Itoa(DefaultSinkPort))

	time.Sleep(100 * time.Millisecond)
	// Then measure
	proxyAddr := "localhost:" + strconv.Itoa(monitor.SinkPort)
	err := ConnectSink(proxyAddr)
	if err != nil {
		t.Errorf("Can not connect to proxy : %s", err)
		return
	}

	meas := NewTimeMeasure("setup")
	meas.Record()
	time.Sleep(100 * time.Millisecond)
	meas.Record()

	EndAndCleanup()

	select {
	case <-done:
		s := monitor.stats
		s.Collect()
		if s.String() == fresh {
			t.Error("stats not updated?")
		}
		return
	case <-time.After(2 * time.Second):
		t.Error("Monitor not finished")
	}
}
