package monitor

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dedis/onet/log"
)

func TestNewDataFilter(t *testing.T) {
	rc := make(map[string]string)
	rc["filter_round"] = "50"
	rc["filter_verify"] = "90"
	df := NewDataFilter(rc)
	if df.percentiles["round"] == 0 || df.percentiles["verify"] == 0 {
		t.Error("Datafilter not correctly parsed the run config")
	}
	if df.percentiles["round"] != 50.0 || df.percentiles["verify"] != 90.0 {
		t.Error(fmt.Sprintf("datafilter not correctly parsed the percentile: %f vs 50 or %f vs 90", df.percentiles["round"], df.percentiles["verifiy"]))
	}
}

func TestDataFilterFilter(t *testing.T) {
	rc := make(map[string]string)
	rc["filter_round"] = "75"
	df := NewDataFilter(rc)

	values := []float64{35, 20, 15, 40, 50}
	filtered := df.Filter("round", values)
	shouldBe := []float64{35, 20, 15, 40}
	if len(shouldBe) != len(filtered) {
		t.Error(fmt.Sprintf("Filter returned %d values instead of %d", len(filtered), len(shouldBe)))
	}
	for i, v := range filtered {
		if v != shouldBe[i] {
			t.Error(fmt.Sprintf("Element %d = %f vs %f", i, filtered[i], shouldBe[i]))
		}
	}
}

func TestStatsUpdate(t *testing.T) {
	rc := make(map[string]string)
	rc["servers"] = "2"
	rc["hosts"] = "2"
	stats := NewStats(rc)

	m1 := newSingleMeasure("round_wall", 10)
	m2 := newSingleMeasure("round_wall", 30)
	stats.Update(m1)
	stats.Update(m2)
	stats.Collect()
	val := stats.values["round_wall"]
	if val.Avg() != 20 {
		t.Error("Aggregate or Update not working")
	}
}
func TestStatsOrder(t *testing.T) {
	m := make(map[string]string)
	m["servers"] = "1"
	m["hosts"] = "1"
	m["bf"] = "2"
	// create stats
	stat := NewStats(m)
	m1 := newSingleMeasure("round", 10)
	m2 := newSingleMeasure("setup", 5)
	stat.Update(m1)
	stat.Update(m2)
	str := new(bytes.Buffer)
	stat.WriteHeader(str)
	stat.WriteValues(str)

	stat2 := NewStats(m)
	stat2.Update(m2)
	stat2.Update(m1)

	str2 := new(bytes.Buffer)
	stat2.WriteHeader(str2)
	stat2.WriteValues(str2)
	if !bytes.Equal(str.Bytes(), str2.Bytes()) {
		t.Fatal("KeyOrder / output not the same for same stats")
	}
}

func TestValues(t *testing.T) {
	v1 := NewValue("test")
	v1.Store(5.0)
	v1.Store(10.0)
	v1.Store(15.0)

	v1.Collect()
	if v1.Avg() != 10.0 || v1.Min() != 5.0 || v1.Max() != 15.0 || v1.Sum() != 30.0 || v1.Dev() != 5.0 {
		t.Fatal("Wrong value calculation")
	}
}

func TestStatsAverage(t *testing.T) {
	m := make(map[string]string)
	m["servers"] = "1"
	m["hosts"] = "1"
	m["bf"] = "2"
	// create stats
	stat1 := NewStats(m)
	stat2 := NewStats(m)
	m1 := newSingleMeasure("round", 10)
	m2 := newSingleMeasure("setup", 5)
	stat1.Update(m1)
	stat2.Update(m2)

	str := new(bytes.Buffer)
	avgStat := AverageStats([]*Stats{stat1, stat2})
	avgStat.WriteHeader(str)
	avgStat.WriteValues(str)

	stat3 := NewStats(m)
	stat4 := NewStats(m)
	stat3.Update(m1)
	stat4.Update(m2)

	str2 := new(bytes.Buffer)
	avgStat2 := AverageStats([]*Stats{stat3, stat4})
	avgStat2.WriteHeader(str2)
	avgStat2.WriteValues(str2)

	if !bytes.Equal(str.Bytes(), str2.Bytes()) {
		t.Fatal("Average are not the same !")
	}
}

func TestStatsAverageFiltered(t *testing.T) {
	m := make(map[string]string)
	m["servers"] = "1"
	m["hosts"] = "1"
	m["bf"] = "2"
	// create the filter entry
	m["filter_round"] = "50"
	// create stats
	stat1 := NewStats(m)
	stat2 := NewStats(m)
	m1 := newSingleMeasure("round", 10)
	m2 := newSingleMeasure("round", 20)
	m3 := newSingleMeasure("round", 150)
	stat1.Update(m1)
	stat1.Update(m2)
	stat1.Update(m3)
	stat2.Update(m1)
	stat2.Update(m2)
	stat2.Update(m3)

	/* stat2.Collect()*/
	//val := stat2.Value("round")
	//if val.Avg() != (10+20)/2 {
	//t.Fatal("Average with filter does not work?")
	//}

	str := new(bytes.Buffer)
	avgStat := AverageStats([]*Stats{stat1, stat2})
	avgStat.WriteHeader(str)
	avgStat.WriteValues(str)

	stat3 := NewStats(m)
	stat4 := NewStats(m)
	stat3.Update(m1)
	stat3.Update(m2)
	stat3.Update(m3)
	stat4.Update(m1)
	stat4.Update(m2)
	stat4.Update(m3)

	str2 := new(bytes.Buffer)
	avgStat2 := AverageStats([]*Stats{stat3, stat4})
	avgStat2.WriteHeader(str2)
	avgStat2.WriteValues(str2)

	if !bytes.Equal(str.Bytes(), str2.Bytes()) {
		t.Fatal("Average are not the same !")
	}

}

func TestStatsString(t *testing.T) {
	rc := map[string]string{"servers": "10", "hosts": "10"}
	rs := NewStats(rc)
	m := NewMonitor(rs)

	go func() {
		if err := m.Listen(); err != nil {
			log.Fatal("Could not Listen():", err)
		}
	}()
	defer EndAndCleanup()
	time.Sleep(100 * time.Millisecond)
	ConnectSink("localhost:" + strconv.Itoa(DefaultSinkPort))
	measure := NewTimeMeasure("test")
	time.Sleep(time.Millisecond * 100)
	measure.Record()
	time.Sleep(time.Millisecond * 100)

	if !strings.Contains(rs.String(), "0.1") {
		t.Fatal("The measurement should contain 0.1:", rs.String())
	}
}
