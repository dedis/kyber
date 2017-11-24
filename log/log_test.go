package log

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContains(t *testing.T) {
	// Flush buffers from previous tests.
	GetStdOut()
	GetStdErr()
	old := DebugVisible()
	SetDebugVisible(1)

	assert.False(t, containsStdOut("info"))
	assert.False(t, containsStdErr("error"))
	Info("Some information")
	assert.True(t, containsStdOut("info"))
	Error("Some error")
	assert.True(t, containsStdErr("error"))

	SetDebugVisible(old)
}

// containsStdErr will look for str in StdErr and flush the output-buffer.
// If you need to look at multiple strings, use GetStdErr.
func containsStdErr(str string) bool {
	return strings.Contains(GetStdErr(), str)
}

// containsStdOut will look for str in StdOut and flush the output-buffer.
// If you need to look at multiple strings, use GetStdOut.
func containsStdOut(str string) bool {
	return strings.Contains(GetStdOut(), str)
}
