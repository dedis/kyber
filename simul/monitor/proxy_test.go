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
	done := make(chan bool, 2)
	go func() {
		monitor.Listen()
		done <- true
	}()

	// Then setup proxy
	// change port so the proxy does not listen to the same
	// than the original monitor

	// proxy listens to 0.0.0.0:8000 & redirects to
	// localhost:10000 (DefaultSinkPort)
	go func() {
		time.Sleep(100 * time.Millisecond)
		Proxy("localhost:" + strconv.Itoa(DefaultSinkPort))
		done <- true
	}()

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
	close(proxyDone)

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
