//go:build windows

package scanner

import (
	"os/exec"
	"strconv"
	"syscall"
)

// procAttr returns SysProcAttr configured for process-group management so the
// whole engine tree (parent + grandchildren) can be killed on timeout.
// CREATE_NEW_PROCESS_GROUP (0x200) makes the new process the root of a group
// that can be terminated as a unit.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// killProcessTree kills the process tree rooted at pid using taskkill /F /T,
// which terminates the process and all its descendants.
func killProcessTree(pid int) error {
	return exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid)).Run()
}
