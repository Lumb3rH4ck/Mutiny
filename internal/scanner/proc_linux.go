//go:build linux

package scanner

import "syscall"

// procAttr returns SysProcAttr configured for process-group management so the
// whole engine tree (parent + grandchildren) can be killed on timeout.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// killProcessTree kills the process group rooted at pid (negative pid = whole
// group via setpgid).
func killProcessTree(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL)
}
