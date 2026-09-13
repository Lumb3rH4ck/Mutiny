package sandbox

import (
	"strings"
	"testing"
)

func TestParseStraceCapturesExecveOutcome(t *testing.T) {
	trace := `12345 execve("/evil.exe", ["/evil.exe"], 0x7fff...) = 0
12345 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
12345 execve("/sample.exe", ["/sample.exe"], 0x7fff...) = -1 ENOEXEC (Exec format error)
12346 execve("/tmp/x.sh", ["/tmp/x.sh"], 0x55...) = 0
`
	_, execs, nets := parseStrace(trace)
	if len(nets) != 0 {
		t.Fatalf("unexpected net attempts: %v", nets)
	}

	var sampleExec, evilExec, scriptExec *ExecAttempt
	for i := range execs {
		switch {
		case strings.HasSuffix(execs[i].Path, "evil.exe"):
			evilExec = &execs[i]
		case strings.HasSuffix(execs[i].Path, "sample.exe"):
			sampleExec = &execs[i]
		case strings.HasSuffix(execs[i].Path, "x.sh"):
			scriptExec = &execs[i]
		}
	}

	if evilExec == nil || !evilExec.Success {
		t.Errorf("evil.exe execve should be a success, got %+v", evilExec)
	}
	if sampleExec == nil {
		t.Fatalf("sample.exe execve not parsed")
	}
	if sampleExec.Success {
		t.Errorf("sample.exe execve should be a failure, got Success=true")
	}
	if sampleExec.Errno != "ENOEXEC" {
		t.Errorf("sample.exe errno = %q, want ENOEXEC", sampleExec.Errno)
	}
	if scriptExec == nil || !scriptExec.Success {
		t.Errorf("x.sh execve should be a success, got %+v", scriptExec)
	}
}

func TestClassifyExecution(t *testing.T) {
	sample := "evil.exe"
	exec := func(success bool) ExecAttempt {
		return ExecAttempt{Path: "/" + sample, Success: success}
	}

	if executed, reason := classifyExecution(sample, []ExecAttempt{exec(true)}); !executed || reason != "" {
		t.Errorf("successful exec: executed=%v reason=%q, want executed", executed, reason)
	}
	if executed, reason := classifyExecution(sample, []ExecAttempt{
		{Path: "/" + sample, Success: false, Errno: "ENOEXEC"},
	}); executed || !strings.Contains(reason, "ENOEXEC") {
		t.Errorf("failed exec: executed=%v reason=%q, want errno in reason", executed, reason)
	}
	if executed, reason := classifyExecution(sample, []ExecAttempt{
		{Path: "/x.sh", Success: false, Errno: "ENOEXEC"},
	}); executed || reason != "sample binary was never executed" {
		t.Errorf("no sample exec attempt: executed=%v reason=%q", executed, reason)
	}
}
