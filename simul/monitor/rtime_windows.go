// +build windows

package monitor

import (
	"syscall"

	"github.com/dedis/onet/log"
)

// Returns the system and the user CPU time used by the current process so far.
func getRTime() (tSys, tUsr float64) {
	var creationTime, exitTime, kernelTime, userTime syscall.Filetime
	hProcess, _ := syscall.GetCurrentProcess()
	if err := syscall.GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime); err != nil {
		log.Error("Couldn't get rusage time:", err)
		return -1, -1
	}

	sys := int64(kernelTime.HighDateTime)<<32 + int64(kernelTime.LowDateTime)
	usr := int64(userTime.HighDateTime)<<32 + int64(userTime.LowDateTime)
	return (float64(sys) / 10000000.0), (float64(usr) / 10000000.0)
}
