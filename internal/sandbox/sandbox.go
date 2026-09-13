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
	// Container is the Docker image to use. Reuses the mutiny-scan image
	// which already has strace available.
	Container string
	// Timeout is the maximum runtime per sample. The container is killed
	// after this duration.
	Timeout time.Duration
	// MemoryLimit caps the sandbox container's RAM (docker --memory, e.g.
	// "1g"). Empty disables the limit. The container otherwise inherits the
	// host's memory, so a hostile sample could exhaust RAM; tmpfs mounts in
	// the container (file ops the sample performs in /tmp) are also bounded
	// by this limit.
	MemoryLimit string
	// PidsLimit caps how many processes/threads the sample can spawn (docker
	// --pids-limit). Zero disables the limit. Bounds fork-bomb behaviour
	// inside the sandbox.
	PidsLimit int
	// CPULimit caps how much CPU the sample can burn (docker --cpus, e.g.
	// "1"). Empty disables the limit.
	CPULimit string
}

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

// evaluateBehavior applies heuristic rules to the parsed behavior and returns
// a verdict ("clean", "suspicious", "malicious") and a human summary.
func evaluateBehavior(report BehaviorReport) (verdict, summary string) {
	nFileOps := len(report.FileOps)
	nExecs := len(report.ExecAttempts)
	nNet := len(report.NetAttempts)

	// Count suspicious indicators.
	var indicators []string

	// Check for shell exec + file write (classic malware pattern).
	hasShellExec := false
	hasFileWrite := false
	hasChmod := false
	hasChown := false
	hasMount := false
	writesOutsideTmp := false

	for _, e := range report.ExecAttempts {
		base := filepath.Base(e.Path)
		if base == "sh" || base == "bash" || base == "dash" || base == "zsh" ||
			base == "cmd.exe" || base == "powershell.exe" || base == "pwsh" ||
			base == "python" || base == "python3" || base == "perl" || base == "ruby" ||
			strings.HasSuffix(base, ".sh") {
			hasShellExec = true
		}
	}

	for _, f := range report.FileOps {
		switch f.Syscall {
		case "write", "pwrite64", "writev", "creat":
			hasFileWrite = true
			if !strings.HasPrefix(f.Path, "/tmp") && !strings.HasPrefix(f.Path, "/run") {
				writesOutsideTmp = true
			}
		case "chmod", "fchmod", "fchmodat":
			hasChmod = true
			// Check for dangerous permissions (0777, 0755 on sensitive files).
			if f.Mode == "0777" || f.Mode == "4095" || f.Mode == "S_ISUID|0777" {
				indicators = append(indicators, fmt.Sprintf("dangerous chmod %s on %s", f.Mode, f.Path))
			}
		case "chown", "fchown", "fchownat":
			hasChown = true
			indicators = append(indicators, fmt.Sprintf("chown on %s", f.Path))
		case "mount", "umount2":
			hasMount = true
			indicators = append(indicators, fmt.Sprintf("mount/umount syscall: %s", f.Syscall))
		}
	}

	for _, n := range report.NetAttempts {
		if n.Syscall == "connect" || n.Syscall == "sendto" {
			indicators = append(indicators, fmt.Sprintf("network %s to %s:%s", n.Syscall, n.Addr, n.Port))
		}
	}

	// Scoring: malicious if multiple high-confidence indicators line up.
	score := 0
	if hasShellExec && hasFileWrite {
		score += 3
		indicators = append(indicators, "shell exec + file write pattern")
	}
	if writesOutsideTmp {
		score += 2
		indicators = append(indicators, "file writes outside /tmp")
	}
	if hasChmod {
		score += 1
	}
	if hasChown {
		score += 2
	}
	if hasMount {
		score += 3
	}
	if nNet > 3 {
		score += 2
		indicators = append(indicators, fmt.Sprintf("%d network attempts", nNet))
	} else if nNet > 0 {
		score += 1
	}
	if nExecs > 5 {
		score += 2
		indicators = append(indicators, fmt.Sprintf("%d exec attempts", nExecs))
	} else if nExecs > 1 {
		score += 1
	}

	switch {
	case score >= 5:
		verdict = "malicious"
	case score >= 2:
		verdict = "suspicious"
	default:
		verdict = "clean"
	}

	// Build summary.
	var parts []string
	if nFileOps > 0 {
		parts = append(parts, fmt.Sprintf("%d file ops", nFileOps))
	}
	if nExecs > 0 {
		parts = append(parts, fmt.Sprintf("%d exec", nExecs))
	}
	if nNet > 0 {
		parts = append(parts, fmt.Sprintf("%d net attempts", nNet))
	}
	if len(indicators) > 0 {
		parts = append(parts, strings.Join(indicators[:min(3, len(indicators))], "; "))
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
