package monitor

import (
	"bytes"
	"testing"
	"time"
)

type DummyCounterIO struct {
	rvalue uint64
	wvalue uint64
}

func (dm *DummyCounterIO) Rx() uint64 {
	dm.rvalue += 10
	return dm.rvalue
}

func (dm *DummyCounterIO) Tx() uint64 {
	dm.wvalue += 10
	return dm.wvalue
}

func TestCounterIOMeasureRecord(t *testing.T) {
	mon, _ := setupMonitor(t)
	dm := &DummyCounterIO{0, 0}
	// create the counter measure
	cm := NewCounterIOMeasure("dummy", dm)
	if cm.baseRx != dm.rvalue || cm.baseTx != dm.wvalue {
		t.Logf("baseRx = %d vs rvalue = %d || baseTx = %d vs wvalue = %d", cm.baseRx, dm.rvalue, cm.baseTx, dm.wvalue)
		t.Fatal("Tx() / Rx() not working ?")
	}
	//bread, bwritten := cm.baseRx, cm.baseTx
	cm.Record()
	// check the values again
	if cm.baseRx != dm.rvalue || cm.baseTx != dm.wvalue {
		t.Fatal("Record() not working for CounterIOMeasure")
	}

	// Important otherwise data don't get written down to the monitor yet.
	time.Sleep(100 * time.Millisecond)
	str := new(bytes.Buffer)
	stat := mon.stats
	stat.Collect()
	stat.WriteHeader(str)
	stat.WriteValues(str)
	wr, re := stat.Value("dummy_tx"), stat.Value("dummy_rx")
	if wr == nil || wr.Avg() != 10 {
		t.Logf("stats => %v", stat.values)
		if wr != nil {
			t.Logf("wr.Avg() = %f", wr.Avg())
		}
		t.Fatal("Stats doesn't have the right value (write)")
	}
	if re == nil || re.Avg() != 10 {
		t.Fatal("Stats doesn't have the right value (read)")
	}
	EndAndCleanup()
	time.Sleep(100 * time.Millisecond)
}
