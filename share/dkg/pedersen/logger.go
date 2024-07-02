package dkg

// Logger is a simpler key value logger interface
type Logger interface {
	Info(keyvals ...interface{})
	Error(keyvals ...interface{})
}
