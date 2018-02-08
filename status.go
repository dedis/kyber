package onet

// Status holds key/value pairs of the status to be returned to the requester.
type Status map[string]string

// StatusReporter is the interface that all structures that want to return a status will implement.
type StatusReporter interface {
	GetStatus() Status
}

// statusReporterStruct holds a map of all StatusReporters.
type statusReporterStruct struct {
	statusReporters map[string]StatusReporter
}

// newStatusReporterStruct creates a new instance of the newStatusReporterStruct.
func newStatusReporterStruct() *statusReporterStruct {
	return &statusReporterStruct{
		statusReporters: make(map[string]StatusReporter),
	}
}

// RegisterStatusReporter registers a status reporter.
func (s *statusReporterStruct) RegisterStatusReporter(name string, sr StatusReporter) {
	s.statusReporters[name] = sr

}

// ReportStatus gets the status of all StatusReporters within the Registry and
// puts them in a map
func (s *statusReporterStruct) ReportStatus() map[string]Status {
	m := make(map[string]Status)
	for key, val := range s.statusReporters {
		m[key] = val.GetStatus()
	}
	return m
}
