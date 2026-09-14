//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// New creates a Sandbox. container is the Docker image name (e.g. "mutiny-scan").
func New(container string, timeout time.Duration) *Sandbox {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &Sandbox{
		Container: container,
		Timeout:   timeout,
	}
}

// toolLookup resolves host-side helper binaries. Defaults to identity (PATH
// lookup); mutiny can install an absolute-path resolver (see
// SetTrustedToolLookup) so a hijacked PATH cannot swap in a hostile `file`.
var toolLookup = func(name string) string { return name }

// SetTrustedToolLookup installs a resolver for host-side helper binaries
// (currently used for `file` magic detection). Passing nil restores PATH
// lookup.
func SetTrustedToolLookup(fn func(string) string) {
	if fn == nil {
		toolLookup = func(name string) string { return name }
		return
	}
	toolLookup = fn
}

// IsExecutable returns true if the file at path is considered executable-ish
// based on its extension or magic bytes. Only executable files are sandboxed.
func IsExecutable(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	execExts := map[string]bool{
		".exe": true, ".scr": true, ".bat": true, ".cmd": true,
		".ps1": true, ".vbs": true, ".vbe": true, ".js": true,
		".jse": true, ".wsf": true, ".wsh": true, ".msi": true,
		".com": true, ".pif": true,
		".elf": true, ".sh": true, ".bash": true,
		".py": true, ".rb": true, ".pl": true, ".php": true,
		".jar": true, ".class": true,
		".dll": true, ".so": true, ".dylib": true,
		".apk": true, ".app": true, ".command": true,
	}
	if execExts[ext] {
		return true
	}

	// Fallback: check magic bytes for ELF / PE / Mach-O.
	f, err := exec.Command(toolLookup("file"), "--brief", path).Output()
	if err != nil {
		return false
	}
	brief := strings.ToLower(string(f))
	return strings.Contains(brief, "elf") ||
		strings.Contains(brief, "pe32") ||
		strings.Contains(brief, "ms-dos") ||
		strings.Contains(brief, "mach-o")
}

// Analyze executes the sample inside a throwaway container and returns a
// BehaviorReport. The container is always cleaned up (--rm).
func (s *Sandbox) Analyze(ctx context.Context, filePath string) BehaviorReport {
	report := BehaviorReport{}

	if s.Container == "" {
		report.Error = "sandbox container not configured"
		return report
	}

	// Apply per-sample timeout.
	timeout := s.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Mount the sample read-only inside the container.
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		report.Error = fmt.Sprintf("resolve path: %v", err)
		return report
	}
	sampleName := filepath.Base(absPath)

	// Generate a unique container name for this run.
	containerName := fmt.Sprintf("mutiny-sandbox-%d", time.Now().UnixNano())

	// Start the throwaway container: network cut, read-only, no caps,
	// unprivileged user, sample mounted read-only.
	runArgs := []string{
		"run", "--rm",
		// Detached: docker run must return as soon as the container is up so
		// the strace pass below can docker exec into it. Without -d docker run
		// blocks on the sleep-infinity entrypoint until the timeout, which
		// then SIGKILLs it and the sandbox never analyzes anything.
		"-d",
		"--name", containerName,
		"--network=none",
		"--cap-drop=ALL",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--tmpfs", "/run:rw,noexec,nosuid,size=1m",
		"--security-opt=no-new-privileges:true",
		"--user=nobody",
		"-v", absPath + ":/" + sampleName + ":ro",
	}
	if s.MemoryLimit != "" {
		runArgs = append(runArgs, "--memory", s.MemoryLimit)
	}
	if s.PidsLimit > 0 {
		runArgs = append(runArgs, "--pids-limit", strconv.Itoa(s.PidsLimit))
	}
	if s.CPULimit != "" {
		runArgs = append(runArgs, "--cpus", s.CPULimit)
	}
	runArgs = append(runArgs,
		// Keep the container alive so we can exec strace into it.
		"--entrypoint", "sleep",
		s.Container, "infinity",
	)

	// Start the container.
	startCmd := exec.CommandContext(ctx, "docker", runArgs...)
	var startBuf bytes.Buffer
	startCmd.Stdout = &startBuf
	startCmd.Stderr = &startBuf
	if err := startCmd.Run(); err != nil {
		report.Error = fmt.Sprintf("start sandbox container: %v: %s", err, strings.TrimSpace(startBuf.String()))
		return report
	}

	// Ensure cleanup even if we panic or the context is cancelled.
	defer func() {
		killCmd := exec.Command("docker", "rm", "-f", containerName)
		killCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		_ = killCmd.Run()
	}()

	// Run strace inside the container. -f follows forks, -e traces
	// file+process+network syscalls, output goes to /tmp/trace.log.
	samplePath := "/" + sampleName
	straceArgs := []string{
		"exec", containerName,
		"strace", "-f",
		"-o", "/tmp/trace.log",
		"-e", "trace=file,process,network",
		// Run the sample directly. If it's a script, the kernel will
		// invoke the interpreter via the shebang line.
		samplePath,
	}

	straceCmd := exec.CommandContext(ctx, "docker", straceArgs...)
	var straceBuf bytes.Buffer
	straceCmd.Stdout = &straceBuf
	straceCmd.Stderr = &straceBuf
	_ = straceCmd.Run() // non-zero exit is expected (sample may crash/exit)

	// Read back the trace log.
	traceCmd := exec.CommandContext(ctx, "docker", "exec", containerName, "cat", "/tmp/trace.log")
	var traceBuf bytes.Buffer
	traceCmd.Stdout = &traceBuf
	traceCmd.Stderr = &traceBuf
	if err := traceCmd.Run(); err != nil {
		// Fallback: try to use strace's stderr output which sometimes
		// contains partial trace data when /tmp isn't writable.
		report.RawTrace = strings.TrimSpace(straceBuf.String())
		if report.RawTrace == "" {
			report.Error = fmt.Sprintf("read trace log: %v", err)
			return report
		}
	} else {
		report.RawTrace = strings.TrimSpace(traceBuf.String())
	}

	if report.RawTrace == "" {
		// No syscalls at all: we can't even confirm the sample was attempted.
		// Clean would be a false negative (e.g. a Windows PE that never ran).
		report.Executed = false
		report.NotExecutedReason = "no syscalls captured (sample never started)"
		report.Verdict = "unknown"
		report.Summary = "behavior analysis captured nothing — treated as unscanned"
		return report
	}

	// Parse the strace output.
	report.FileOps, report.ExecAttempts, report.NetAttempts = parseStrace(report.RawTrace)

	// Did the sample's own executable actually launch? A trace that only holds
	// a failed execve of the sample (Windows PE, .bat/.ps1 with no Linux
	// interpreter, ...) exercised zero behavior, so the heuristic must not be
	// allowed to score it "clean": surface it as explicitly not-executed and
	// let the caller treat it as unscanned rather than benign.
	report.Executed, report.NotExecutedReason = classifyExecution(sampleName, report.ExecAttempts)
	if !report.Executed && len(report.ExecAttempts) > 0 {
		report.Verdict = "unknown"
		report.Summary = "not executed (" + report.NotExecutedReason + ") — no behavior observed, treated as unscanned"
		return report
	}

	// Apply heuristic verdict.
	report.Verdict, report.Summary = evaluateBehavior(report)

	return report
}

// classifyExecution reports whether the sample's own executable launched
// successfully inside the container. execve attempts are keyed by the mounted
// sample path; any successful one means behavior was actually exercised.
func classifyExecution(sampleName string, attempts []ExecAttempt) (executed bool, reason string) {
	for _, e := range attempts {
		if filepath.Base(e.Path) == sampleName {
			if e.Success {
				return true, ""
			}
			executed = false
			reason = "sample exec failed " + e.Errno
		}
	}
	if reason == "" {
		reason = "sample binary was never executed"
	}
	return false, reason
}

// strace line patterns:
//   PID   syscall(args) = result
//   PID   syscall(args) = -1 ERRNO (Message)
//
// We capture the main patterns for file, process, and network syscalls.

var straceLineRe = regexp.MustCompile(`^\s*\d+\s+(\w+)\((.+?)\)\s*=\s*(-?\d+)`)
var straceErrRe = regexp.MustCompile(`^\s*\d+\s+(\w+)\((.+?)\)\s*=\s*-1\s+(\w+)\s+\((.+)\)`)

// File syscalls we care about.
var fileSyscalls = map[string]bool{
	"open": true, "openat": true, "creat": true,
	"unlink": true, "unlinkat": true,
	"rename": true, "renameat": true, "renameat2": true,
	"chmod": true, "fchmod": true, "fchmodat": true,
	"chown": true, "fchown": true, "fchownat": true,
	"write": true, "pwrite64": true, "writev": true,
	"mkdir": true, "mkdirat": true,
	"rmdir":    true,
	"truncate": true, "ftruncate": true,
	"mount": true, "umount2": true,
	"symlink": true, "symlinkat": true,
	"link": true, "linkat": true,
}

// Process syscalls we care about.
var processSyscalls = map[string]bool{
	"execve": true,
	"fork":   true, "vfork": true,
	"clone": true, "clone3": true,
	"ptrace": true,
	"kill":   true, "tkill": true, "tgkill": true,
}

// Network syscalls we care about.
var networkSyscalls = map[string]bool{
	"socket":  true,
	"connect": true,
	"sendto":  true, "sendmsg": true,
	"recvfrom": true, "recvmsg": true,
	"bind":   true,
	"listen": true,
	"accept": true, "accept4": true,
}

func parseStrace(raw string) ([]FileOp, []ExecAttempt, []NetAttempt) {
	var fileOps []FileOp
	var execs []ExecAttempt
	var nets []NetAttempt

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		// Try error pattern first (captures args even on failure).
		if m := straceErrRe.FindStringSubmatch(line); m != nil {
			// m: [full, syscall, args, errno, message]
			parseLine(m[1], m[2], false, m[3], &fileOps, &execs, &nets)
			continue
		}
		if m := straceLineRe.FindStringSubmatch(line); m != nil {
			// A non-negative return means the syscall succeeded.
			success := m[3] != "-1"
			parseLine(m[1], m[2], success, "", &fileOps, &execs, &nets)
		}
	}
	return fileOps, execs, nets
}

func parseLine(syscallName, args string, success bool, errno string, fileOps *[]FileOp, execs *[]ExecAttempt, nets *[]NetAttempt) {
	switch {
	case fileSyscalls[syscallName]:
		op := FileOp{Syscall: syscallName}
		// Extract the first argument (usually the path).
		op.Path = extractPath(args)
		if syscallName == "chmod" || syscallName == "fchmod" || syscallName == "fchmodat" {
			op.Mode = extractMode(args)
		}
		*fileOps = append(*fileOps, op)

	case processSyscalls[syscallName]:
		if syscallName == "execve" {
			attempt := ExecAttempt{Success: success, Errno: errno}
			parts := splitArgs(args)
			if len(parts) > 0 {
				attempt.Path = unquote(parts[0])
			}
			if len(parts) > 1 {
				// The second arg is typically the argv array.
				attempt.Args = parseArgv(parts[1])
			}
			*execs = append(*execs, attempt)
		} else {
			// fork/clone/vfork — record as a generic exec attempt.
			*execs = append(*execs, ExecAttempt{Path: "(" + syscallName + ")"})
		}

	case networkSyscalls[syscallName]:
		attempt := NetAttempt{Syscall: syscallName}
		attempt.Addr, attempt.Port = extractAddr(args)
		*nets = append(*nets, attempt)
	}
}

// extractPath pulls the first quoted string from args, which is typically
// the file path in open/openat/creat/unlink/chmod/etc.
func extractPath(args string) string {
	// Find first quoted string.
	inQuote := false
	start := -1
	for i, c := range args {
		if c == '"' && (i == 0 || args[i-1] != '\\') {
			if !inQuote {
				inQuote = true
				start = i + 1
			} else {
				return args[start:i]
			}
		}
	}
	// No quoted string — try first unquoted token.
	parts := strings.SplitN(args, ",", 2)
	if len(parts) > 0 {
		return strings.TrimSpace(unquote(parts[0]))
	}
	return args
}

func extractMode(args string) string {
	// For chmod(path, mode), extract the mode argument.
	parts := strings.Split(args, ",")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func splitArgs(args string) []string {
	// Simple split on commas, respecting quotes.
	var result []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(args); i++ {
		c := args[i]
		switch {
		case c == '"' && (i == 0 || args[i-1] != '\\'):
			inQuote = !inQuote
			current.WriteByte(c)
		case c == ',' && !inQuote:
			result = append(result, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseArgv extracts the string values from a C-style argv array representation
// like: ["/bin/sh", "-c", "echo hello"].
func parseArgv(argvStr string) []string {
	argvStr = strings.TrimSpace(argvStr)
	if !strings.HasPrefix(argvStr, "[") {
		return nil
	}
	argvStr = strings.Trim(argvStr, "[]")
	var result []string
	for _, part := range strings.Split(argvStr, ",") {
		s := strings.TrimSpace(part)
		if s != "" {
			result = append(result, unquote(s))
		}
	}
	return result
}

// extractAddr parses socket address info from connect/sendto/bind args.
// Typical formats:
//
//	connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16)
//	sendto(3, "...", 64, 0, {sa_family=AF_INET, sin_port=htons(80), ...}, 16)
func extractAddr(args string) (addr, port string) {
	// Try to find inet_addr("x.x.x.x").
	re := regexp.MustCompile(`inet_addr\("([^"]+)"\)`)
	if m := re.FindStringSubmatch(args); len(m) > 1 {
		addr = m[1]
	}
	// Try to find htons(NNNN).
	re2 := regexp.MustCompile(`htons\((\d+)\)`)
	if m := re2.FindStringSubmatch(args); len(m) > 1 {
		port = m[1]
	}
	// For Unix domain sockets.
	if strings.Contains(args, "AF_UNIX") || strings.Contains(args, "AF_LOCAL") {
		re3 := regexp.MustCompile(`sun_path="([^"]+)"`)
		if m := re3.FindStringSubmatch(args); len(m) > 1 {
			addr = m[1]
		}
		if addr == "" {
			addr = "unix"
		}
	}
	return addr, port
}

// behaviorSignals holds the extracted scoring signals from a behavior report.
type behaviorSignals struct {
	hasShellExec     bool
	hasFileWrite     bool
	writesOutsideTmp bool
	hasChmod         bool
	hasChown         bool
	hasMount         bool
	nNet             int
	nExecs           int
	indicators       []string
}

func isShellBinary(base string) bool {
	switch base {
	case "sh", "bash", "dash", "zsh", "cmd.exe", "powershell.exe", "pwsh",
		"python", "python3", "perl", "ruby":
		return true
	}
	return strings.HasSuffix(base, ".sh")
}

func extractSignals(report BehaviorReport) behaviorSignals {
	var s behaviorSignals
	s.nNet = len(report.NetAttempts)
	s.nExecs = len(report.ExecAttempts)

	for _, e := range report.ExecAttempts {
		if isShellBinary(filepath.Base(e.Path)) {
			s.hasShellExec = true
		}
	}

	for _, f := range report.FileOps {
		switch f.Syscall {
		case "write", "pwrite64", "writev", "creat":
			s.hasFileWrite = true
			if !strings.HasPrefix(f.Path, "/tmp") && !strings.HasPrefix(f.Path, "/run") {
				s.writesOutsideTmp = true
			}
		case "chmod", "fchmod", "fchmodat":
			s.hasChmod = true
			if f.Mode == "0777" || f.Mode == "4095" || f.Mode == "S_ISUID|0777" {
				s.indicators = append(s.indicators, fmt.Sprintf("dangerous chmod %s on %s", f.Mode, f.Path))
			}
		case "chown", "fchown", "fchownat":
			s.hasChown = true
			s.indicators = append(s.indicators, fmt.Sprintf("chown on %s", f.Path))
		case "mount", "umount2":
			s.hasMount = true
			s.indicators = append(s.indicators, fmt.Sprintf("mount/umount syscall: %s", f.Syscall))
		}
	}

	for _, n := range report.NetAttempts {
		if n.Syscall == "connect" || n.Syscall == "sendto" {
			s.indicators = append(s.indicators, fmt.Sprintf("network %s to %s:%s", n.Syscall, n.Addr, n.Port))
		}
	}

	return s
}

func computeScore(s *behaviorSignals) int {
	score := 0
	if s.hasShellExec && s.hasFileWrite {
		score += 3
		s.indicators = append(s.indicators, "shell exec + file write pattern")
	}
	if s.writesOutsideTmp {
		score += 2
		s.indicators = append(s.indicators, "file writes outside /tmp")
	}
	if s.hasChmod {
		score += 1
	}
	if s.hasChown {
		score += 2
	}
	if s.hasMount {
		score += 3
	}
	switch {
	case s.nNet > 3:
		score += 2
		s.indicators = append(s.indicators, fmt.Sprintf("%d network attempts", s.nNet))
	case s.nNet > 0:
		score += 1
	}
	switch {
	case s.nExecs > 5:
		score += 2
		s.indicators = append(s.indicators, fmt.Sprintf("%d exec attempts", s.nExecs))
	case s.nExecs > 1:
		score += 1
	}
	return score
}

func behaviorVerdict(score int) string {
	switch {
	case score >= 5:
		return "malicious"
	case score >= 2:
		return "suspicious"
	default:
		return "clean"
	}
}

// evaluateBehavior applies heuristic rules to the parsed behavior and returns
// a verdict ("clean", "suspicious", "malicious") and a human summary.
func evaluateBehavior(report BehaviorReport) (verdict, summary string) {
	s := extractSignals(report)
	score := computeScore(&s)
	verdict = behaviorVerdict(score)

	nFileOps := len(report.FileOps)
	var parts []string
	if nFileOps > 0 {
		parts = append(parts, fmt.Sprintf("%d file ops", nFileOps))
	}
	if s.nExecs > 0 {
		parts = append(parts, fmt.Sprintf("%d exec", s.nExecs))
	}
	if s.nNet > 0 {
		parts = append(parts, fmt.Sprintf("%d net attempts", s.nNet))
	}
	if len(s.indicators) > 0 {
		parts = append(parts, strings.Join(s.indicators[:min(3, len(s.indicators))], "; "))
	}
	if len(parts) == 0 {
		return "clean", "no suspicious behavior"
	}
	summary = strings.Join(parts, ", ")
	return verdict, summary
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
