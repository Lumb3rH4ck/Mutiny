package sandbox

import "time"

// BehaviorReport captures the observable behavior of a sample executed inside
// an isolated throwaway container. The verdict is determined by heuristics
// applied to the captured syscalls.
type BehaviorReport struct {
	FileOps           []FileOp      `json:"file_ops"`
	ExecAttempts      []ExecAttempt `json:"exec_attempts"`
	NetAttempts       []NetAttempt  `json:"net_attempts"`
	VoidVerdict       string        `json:"-"` // raw heuristic label
	Verdict           string        `json:"verdict"`
	Summary           string        `json:"summary"`
	RawTrace          string        `json:"raw_trace"`
	Error             string        `json:"error,omitempty"`
	Executed          bool          `json:"executed"`
	NotExecutedReason string        `json:"not_executed_reason,omitempty"`
}

// FileOp records a single file-related syscall captured by strace.
type FileOp struct {
	Syscall string `json:"syscall"` // open, openat, creat, unlink, rename, chmod, chown, write, read, mkdir, rmdir
	Path    string `json:"path"`
	Mode    string `json:"mode,omitempty"` // permissions string for chmod/chown, flags for open
}

// ExecAttempt records a process-creation syscall.
type ExecAttempt struct {
	Path    string   `json:"path"`
	Args    []string `json:"args,omitempty"`
	Success bool     `json:"success"` // true when the syscall returned >= 0
	Errno   string   `json:"errno,omitempty"`
}

// NetAttempt records a network-related syscall (all fail with ENETUNREACH
// since the container has --network=none, but the attempt itself is the signal).
type NetAttempt struct {
	Syscall string `json:"syscall"` // socket, connect, sendto, recvfrom, bind, listen
	Addr    string `json:"addr"`
	Port    string `json:"port,omitempty"`
}

// Sandbox manages throwaway container execution for behavior analysis.
type Sandbox struct {
	Container   string
	Timeout     time.Duration
	MemoryLimit string
	PidsLimit   int
	CPULimit    string
}
