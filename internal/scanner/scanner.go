package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ScanResult struct {
	Path    string `json:"path"`
	Clean   bool   `json:"clean"`
	Threat  string `json:"threat"`
	Scanner string `json:"scanner"`
	Error   string `json:"error,omitempty"`
	// Steps records each engine's individual outcome for this file so the
	// caller can persist/surface per-engine pass/fail detail (scan reports,
	// TUI history popup) instead of only the aggregated verdict.
	Steps []EngineStep `json:"steps,omitempty"`
}

// EngineStep records one engine's outcome for a single file scan.
type EngineStep struct {
	Name   string `json:"name"`             // "clamav" | "yara" | "sandbox"
	Result string `json:"result"`           // clean | threat | unscanned
	Detail string `json:"detail,omitempty"` // threat signature, error, or behavior verdict
}

// engineStep converts one engine's ScanResult into a compact per-engine step.
func engineStep(name string, r ScanResult) EngineStep {
	st := EngineStep{Name: name}
	switch {
	case r.Threat != "":
		st.Result = "threat"
		st.Detail = r.Threat
	case r.Error != "":
		st.Result = "unscanned"
		st.Detail = r.Error
	case r.Clean:
		st.Result = "clean"
	default:
		st.Result = "unscanned"
	}
	return st
}

type Scanner struct {
	clamavSocket  string
	yaraRulesDir  string
	quarantineDir string
	maxFileSize   int64
	ScanContainer string
	// TrustedTools, when set, resolves host-side scan binaries to well-known
	// absolute paths instead of consulting the process PATH, so a hijacked PATH
	// cannot substitute a hostile tool. Container mode is unaffected (tools run
	// inside the image). Off by default since not every install has the binaries
	// at the standard locations.
	TrustedTools bool
	// WorkRoot is the base dir for per-scan archive extraction. It must be a
	// path visible to ScanContainer (i.e. underneath a bind mount) when
	// container mode is used; otherwise os.TempDir() is used.
	WorkRoot string
	// Progress, when set, is invoked before each engine pass with the step
	// being performed (see ScanStep.Label).
	Progress func(ScanStep)
	// Timeout is the base per-file scan deadline (both engines together). The
	// effective deadline scales with file size (see scaledTimeout): a multi-GB
	// video gets extra budget proportional to how long the engines realistically
	// need to read it, while a hung engine subprocess is still killed (eventually)
	// instead of freezing the torrent in the scanning dir. Zero disables the
	// limit.
	Timeout  time.Duration
	mu       sync.Mutex
	rulesMu  sync.Mutex
	rules    []string
	rulesErr string
	dirMTime time.Time
	// extractionOnce caches whether the scan image can extract archives
	// (has bsdtar); extractionOK holds the result.
	extractionOnce sync.Once
	extractionOK   bool
}

func New(clamavSocket, yaraRulesDir, quarantineDir string, maxFileSize int64) (*Scanner, error) {
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return nil, fmt.Errorf("create quarantine dir: %w", err)
	}
	s := &Scanner{
		clamavSocket:  clamavSocket,
		yaraRulesDir:  yaraRulesDir,
		quarantineDir: quarantineDir,
		maxFileSize:   maxFileSize,
	}
	// Prime (and validate) the rule set up front so individual scans stay fast
	// and a single broken rule file can't silently disable YARA. A rules
	// failure is non-fatal: ClamAV still carries the scan.
	s.ruleSet()
	return s, nil
}

// EngineStatus reports which scan engines are currently available.
type EngineStatus struct {
	ClamAV bool
	YARA   bool
}

// Status reports engine availability with cheap probes:
//   - YARA: a compiled rule set exists.
//   - ClamAV: the daemon socket is present (local mode) or the scan container
//     is running (container mode).
func (s *Scanner) Status() EngineStatus {
	var st EngineStatus

	if rules, errStr := s.ruleSet(); len(rules) > 0 && errStr == "" {
		st.YARA = true
	}

	if s.ScanContainer != "" {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", s.ScanContainer).CombinedOutput()
		st.ClamAV = err == nil && strings.TrimSpace(string(out)) == "true"
	} else if s.clamavSocket != "" {
		if fi, err := os.Stat(s.clamavSocket); err == nil && fi.Mode()&os.ModeSocket != 0 {
			st.ClamAV = true
		}
	}
	return st
}

func (s *Scanner) ScanFile(path string) ScanResult {
	return s.ScanFileStep(path, ScanStep{})
}

// scanRateFloor is the pessimistic per-byte I/O allowance used to extend the
// per-file scan deadline for large files. It is deliberately conservative (a
// floor, not a target): a legitimately slow read — a network mount or spinning
// disk — still gets enough headroom to finish, while a genuinely hung engine is
// killed once the (much larger) budget is spent.
const scanRateFloor int64 = 32 * 1024 * 1024 // 32 MiB/s

// scaledTimeout returns the effective per-file deadline for a file of the given
// size: the configured base Timeout plus a size-proportional allowance
// (size / scanRateFloor). Returns 0 when the base timeout is disabled.
func (s *Scanner) scaledTimeout(size int64) time.Duration {
	if s.Timeout <= 0 {
		return 0
	}
	extra := time.Duration(0)
	if size > 0 {
		extra = time.Duration(size/scanRateFloor) * time.Second
	}
	// Sanity ceiling so a pathological multi-TB size can't turn a scan into an
	// unbounded hang: never extend past 24x the base timeout.
	if max := 24 * s.Timeout; extra > max {
		extra = max
	}
	return s.Timeout + extra
}

// ScanStep describes one per-file engine pass. Both engines run sequentially,
// so a torrent with F files fires 2×F steps: ClamAV passes first, then YARA.
// Index/Total are 1-based within the file set the caller chose.
type ScanStep struct {
	TorrentID string `json:"torrent_id,omitempty"`
	Engine    string `json:"engine"` // "clamav" | "yara"
	File      string `json:"file"`
	Index     int    `json:"index"`
	Total     int    `json:"total"`
}

// Label renders the human progress line, e.g. "ClamAV Scan: 1 of 5" or
// "Yara Check: 2 of 5".
func (st ScanStep) Label() string {
	prefix := "ClamAV Scan"
	switch st.Engine {
	case "yara":
		prefix = "Yara Check"
	case "sandbox":
		prefix = "Behavior Analysis"
	}
	if st.Total <= 0 {
		return prefix
	}
	idx := st.Index
	if idx <= 0 {
		idx = 1
	}
	return fmt.Sprintf("%s: %d of %d", prefix, idx, st.Total)
}

// ScanFileStep scans one file and, when a Progress hook is set and a Total is
// provided, emits one step before each engine pass so callers can label
// ongoing scanning ("ClamAV Scan: 1 of 5", "Yara Check: 1 of 5").
func (s *Scanner) ScanFileStep(path string, step ScanStep) ScanResult {
	// Clamp Step to this file's info if the caller didn't populate it.
	step.File = path

	// Check file size
	info, err := os.Stat(path)
	if err != nil {
		return ScanResult{Path: path, Error: err.Error()}
	}
	if s.maxFileSize > 0 && info.Size() > s.maxFileSize {
		return ScanResult{Path: path, Clean: true, Threat: "skipped (file too large)"}
	}

	// The deadline starts as the configured base and scales with the file's
	// size, so a multi-GB download is not killed before the engines get to
	// read it all while a hung engine is still bounded.
	eff := s.scaledTimeout(info.Size())
	ctx := context.Background()
	cancel := func() {}
	if eff > 0 {
		ctx, cancel = context.WithTimeout(ctx, eff)
	}
	defer cancel()

	emit := func(engine string) ScanStep {
		if s.Progress == nil || step.Total <= 0 {
			return step
		}
		st := step
		st.Engine = engine
		s.Progress(st)
		return st
	}

	// Run both scanners in sequence: ClamAV first, then YARA. This also
	// gives the per-step progress labels their natural order.
	emit("clamav")
	clamResult := s.scanClamAV(ctx, path, eff)
	emit("yara")
	yaraResult := s.scanYARA(ctx, path, eff)

	// Build the per-engine breakdown up front so every verdict — clean,
	// threat, or unscanned — carries each engine's individual outcome.
	steps := []EngineStep{engineStep("clamav", clamResult), engineStep("yara", yaraResult)}

	// A real threat from either engine wins.
	if clamResult.Threat != "" {
		clamResult.Steps = steps
		return clamResult
	}
	if yaraResult.Threat != "" {
		yaraResult.Steps = steps
		return yaraResult
	}
	// Clean requires BOTH engines to agree. If only one ran clean and the
	// other is unavailable, the file was not fully checked: report it as
	// unscanned rather than clean.
	if clamResult.Clean && yaraResult.Clean {
		return ScanResult{Path: path, Clean: true, Scanner: "clamav+yara", Steps: steps}
	}
	// No engine produced a verdict — the file was NOT checked. Report that
	// honestly instead of treating it as clean.
	if strings.Contains(clamResult.Error, "timed out") {
		return ScanResult{Path: path, Error: clamResult.Error, Steps: steps}
	}
	if strings.Contains(yaraResult.Error, "timed out") {
		return ScanResult{Path: path, Error: yaraResult.Error, Steps: steps}
	}
	var missing []string
	if clamResult.Error != "" {
		missing = append(missing, "clamav")
	}
	if yaraResult.Error != "" {
		missing = append(missing, "yara")
	}
	return ScanResult{Path: path, Error: "scanner engine unavailable: " + strings.Join(missing, ", "), Steps: steps}
}

func (s *Scanner) ScanFileWithContext(ctx context.Context, path string) ScanResult {
	resultCh := make(chan ScanResult, 1)
	go func() {
		resultCh <- s.ScanFile(path)
	}()
	select {
	case <-ctx.Done():
		return ScanResult{Path: path, Error: "scan timeout"}
	case r := <-resultCh:
		return r
	}
}

// trustedPaths are the well-known locations checked when TrustedTools is on.
var trustedPaths = []string{"/usr/bin", "/bin", "/usr/local/bin"}

// TrustedBin returns the absolute path for a host-side helper binary when it
// exists at a well-known location and is executable, else the bare name.
// Exported so the sandbox package (and main) can share the same resolver.
func TrustedBin(name string) string {
	for _, dir := range trustedPaths {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode().Perm()&0o111 != 0 {
			return p
		}
	}
	return name
}

// cmd builds an engine command bound to ctx (so a hung subprocess can be
// killed when the per-file scan deadline fires). When ScanContainer is set
// the engines run inside that Docker container (which must have the download
// root and rules dir bind-mounted at the same absolute paths); otherwise
// local binaries are used (absolute paths when TrustedTools is set).
func (s *Scanner) cmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	if s.ScanContainer != "" {
		// The container drops ALL capabilities (no DAC_OVERRIDE), so even its
		// root cannot read downloads created with private 0600 perms — which
		// surfaced as "engine unavailable" for every file of those torrents.
		// Bind mounts preserve uid/gid, so running the engines as the same
		// host uid/gid reads those files and the clamav-owned signature DB.
		dargs := append([]string{"exec", "-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), s.ScanContainer, name}, args...)
		return exec.CommandContext(ctx, "docker", dargs...)
	}
	if s.TrustedTools {
		name = TrustedBin(name)
	}
	return exec.CommandContext(ctx, name, args...)
}

// run starts cmd, sends its output to a buffer, and waits. If the context is
// done first, it kills the ENGINE's whole process group: execution.CommandContext
// only kills the direct child, so a shell/script engine can leave a grandchild
// (e.g. "sleep", or the container side of docker exec) holding the output pipe
// open — which would keep CombinedOutput blocked long past the deadline.
func (s *Scanner) run(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.Bytes(), err
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return buf.Bytes(), ctx.Err()
	}
}

func (s *Scanner) scanClamAV(ctx context.Context, path string, eff time.Duration) ScanResult {
	result := ScanResult{Path: path}

	if s.clamavSocket == "" {
		result.Error = "clamav socket not configured"
		return result
	}

	// Debian bookworm containers ship no clamdscan, only clamscan (same CLI
	// semantics and exit codes). Local mode keeps the faster daemon path.
	var cmd *exec.Cmd
	if s.ScanContainer != "" {
		cmd = s.cmd(ctx, "clamscan", "--stdout", "--no-summary", path)
	} else {
		cmd = s.cmd(ctx, "clamdscan", "--fdpass", "--no-summary", path)
	}
	output, err := s.run(ctx, cmd)
	if err != nil {
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 1 {
			// Virus found
			result.Threat = parseClamAVOutput(string(output))
			result.Scanner = "clamav"
			return result
		}
		// Engine unavailable (not installed, daemon down, socket missing, ...)
		if ctx.Err() != nil && eff > 0 {
			result.Error = fmt.Sprintf("clamav scan timed out after %s", eff)
			return result
		}
		result.Error = fmt.Sprintf("clamav unavailable: %v", err)
		return result
	}

	result.Clean = true
	result.Scanner = "clamav"
	return result
}

func (s *Scanner) scanYARA(ctx context.Context, path string, eff time.Duration) ScanResult {
	result := ScanResult{Path: path}

	// Refresh rules if the directory changed since we last built the set.
	rules, rulesErr := s.ruleSet()
	if len(rules) == 0 {
		result.Error = rulesErr
		return result
	}

	// Modern YARA has no native archive recursion (-l is --max-rules, -r only
	// recurses into directories), so archive contents are checked by first
	// extracting to a throwaway dir and running yara -r over the tree. yara
	// accepts exactly ONE target per invocation, so the raw archive and the
	// extracted tree are scanned separately; any rule match from either wins.
	targets := []string{path}
	recursive := false
	var workdir string
	defer func() {
		if workdir != "" {
			s.removeWorkdir(workdir)
		}
	}()
	if isArchive(path) {
		wd, err := s.extractWorkdir()
		if err == nil {
			workdir = wd
			if err := s.extractArchive(ctx, path, workdir); err != nil {
				// Extraction failed (tool missing, corrupt/encrypted
				// archive): fall back to scanning the raw bytes. Never let
				// an unreadable archive strand a download on its own.
				s.removeWorkdir(workdir)
				workdir = ""
			} else if err := normalizeWorkdir(workdir); err != nil {
				s.removeWorkdir(workdir)
				workdir = ""
			} else {
				targets = append(targets, workdir)
				recursive = true
			}
		}
	}

	var threat string
	failed := 0
	timedOut := false
	for _, target := range targets {
		// yara [-w] [-r] RULE... TARGET
		args := []string{"-w"}
		if recursive {
			args = append(args, "-r")
		}
		args = append(args, rules...)
		args = append(args, target)
		cmd := s.cmd(ctx, "yara", args...)
		output, err := s.run(ctx, cmd)
		if err != nil {
			failed++
			if ctx.Err() != nil {
				timedOut = true
			}
			continue
		}
		outputStr := strings.TrimSpace(string(output))
		if outputStr != "" {
			threat = parseYARAOutput(outputStr)
			break
		}
	}

	if threat != "" {
		result.Threat = threat
		result.Scanner = "yara"
		return result
	}
	if timedOut && eff > 0 {
		result.Error = fmt.Sprintf("yara scan timed out after %s (%d of %d targets)", eff, failed, len(targets))
		return result
	}
	if failed > 0 {
		// Any target yara couldn't scan means we did not actually verify the
		// payload: report unscanned rather than clean.
		result.Error = fmt.Sprintf("yara unavailable (%d of %d targets failed)", failed, len(targets))
		return result
	}

	result.Clean = true
	result.Scanner = "yara"
	return result
}

// archiveSuffixes are file extensions whose contents YARA checks after bsdtar
// extraction. Longest suffixes first so e.g. ".tar.gz" wins over ".gz".
var archiveSuffixes = []string{
	".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lzma",
	".tgz", ".tbz2", ".txz", ".tzst",
	".zip", ".tar", ".gz", ".bz2", ".xz", ".zst",
	".7z", ".rar", ".cab", ".arj", ".cpio", ".lzma", ".lz",
}

func isArchive(path string) bool {
	lower := strings.ToLower(filepath.Base(path))
	for _, s := range archiveSuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

// extractWorkdir creates a disposable directory for archive extraction. It is
// always created on the host for two reasons: the extracted tree must be
// readable where yara -r runs (inside the scan container via the bind-mounted
// download root in container mode), and the throwaway extraction container
// bind-mounts it read-write. The container uses a unique name under the root,
// so concurrent scans never collide.
func (s *Scanner) extractWorkdir() (string, error) {
	root := s.WorkRoot
	if root == "" {
		root = os.TempDir()
	}
	return os.MkdirTemp(root, ".mutiny-yara-*")
}

// removeWorkdir removes an extraction dir.
func (s *Scanner) removeWorkdir(dir string) {
	_ = os.RemoveAll(dir)
}

// extractInContainer reports whether untrusted archives can be unpacked inside
// the scan image (which must provide libarchive's bsdtar). Probed once. A
// image built before libarchive-tools was added degrades to host extraction
// with a loud warning instead of silently using the host self-extractor.
func (s *Scanner) extractInContainer() bool {
	s.extractionOnce.Do(func() {
		if s.ScanContainer == "" {
			return // host mode: local bsdtar is used directly
		}
		probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(probeCtx, "docker", "run", "--rm", "--network=none",
			"--entrypoint", "bsdtar", s.ScanContainer, "--version").CombinedOutput()
		if err == nil && strings.HasPrefix(string(out), "bsdtar") {
			s.extractionOK = true
			return
		}
		log.Printf("WARNING: scan image %q lacks bsdtar (libarchive-tools); archive contents will be extracted on the HOST until the image is rebuilt (`./dev.sh scan-up`).", s.ScanContainer)
	})
	return s.extractionOK
}

// withinExtractionBounds reports whether an extracted tree (entries members,
// size total expanded bytes) is inside the zip-bomb ceilings.
func withinExtractionBounds(entries int, size int64) bool {
	return entries <= extractEntriesCap && size <= extractBytesCap
}

// checkExtractionBounds walks an extracted tree and rejects it if it exceeds
// the expanded-byte or member-count ceilings (zip-bomb guard). The caller
// removes the tree on error.
func checkExtractionBounds(dir string) error {
	var entries int
	var size int64
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		entries++
		if fi, e := d.Info(); e == nil && !fi.IsDir() {
			size += fi.Size()
		}
		if !withinExtractionBounds(entries, size) {
			return errExtractionTooLarge
		}
		return nil
	})
	if errors.Is(err, errExtractionTooLarge) {
		return fmt.Errorf("archive bomb guard: %d members / %d bytes exceeds %d / %d", entries, size, extractEntriesCap, extractBytesCap)
	}
	return err
}

var errExtractionTooLarge = errors.New("extraction exceeds scan ceilings")

// extractArchive unpacks path into workdir. Extraction always runs inside a
// throwaway container built from the scan image (no network, no caps, read-only
// fs, archive mounted read-only); the untar lands on a size-capped tmpfs and is
// only copied out to the yara-visible workdir once it is known to be within the
// byte/entry ceilings below. A hostile "zip bomb" therefore can never grow onto
// a real device. A legacy image without bsdtar falls back to the host binary
// with a warning (see extractInContainer); OWNERSHIP is never restored
// (--no-same-owner).
//
// Ceilings: 2 GiB of expanded bytes and 25,000 members. Archives that exceed
// either fail extraction and scanYARA falls back to scanning the raw bytes.
const (
	extractBytesCap   = 2 << 30    // 2 GiB expanded bytes ceiling
	extractEntriesCap = 25_000     // path-count explosion ceiling
	extractTmpfsPath  = "/extract" // tmpfs mount inside the throwaway container
)

func (s *Scanner) extractArchive(ctx context.Context, path, workdir string) error {
	image := s.ScanContainer
	if image == "" {
		image = "mutiny-scan"
	}
	if !s.extractInContainer() {
		// Legacy host fallback (pre-libarchive-tools image). Idempotent with
		// the container path but unbounded; kept only for stale images.
		out, err := s.run(ctx, s.cmd(ctx, "bsdtar", "-xf", path, "-C", workdir))
		if err != nil {
			return fmt.Errorf("extract archive: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// --user=<host uid> matters under rootless Docker: the container's root
	// maps to a different uid than the host user, which owns the mounted
	// workdir and would be unwritable. Running as the invoking user keeps
	// mounts writable. --no-same-owner skips ownership restoration anyway.
	uidgid := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	name := fmt.Sprintf("mutiny-extract-%d", time.Now().UnixNano())
	tmpfs := extractTmpfsPath + ":rw,nosuid,noexec,size=" + strconv.FormatInt(extractBytesCap, 10)

	cmd := exec.CommandContext(ctx, "docker", "run",
		"--network=none", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--user", uidgid,
		"--name", name,
		"--pids-limit=64",
		"--tmpfs", tmpfs,
		"--entrypoint", "bsdtar",
		"-v", path+":"+path+":ro",
		image, "--no-same-owner", "-xf", path, "-C", extractTmpfsPath,
	)
	out, err := s.run(ctx, cmd)
	defer func() {
		rm := exec.Command("docker", "rm", "-f", name)
		rm.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		_ = rm.Run()
	}()
	if err != nil {
		return fmt.Errorf("extract archive: %v: %s", err, strings.TrimSpace(string(out)))
	}

	// Move the (tmpfs-bounded) tree out where yara -r can read it, then verify
	// it really is within the byte/entry ceilings before returning success.
	if out, err = s.run(ctx, exec.CommandContext(ctx, "docker", "cp", name+":/extract/.", workdir)); err != nil {
		return fmt.Errorf("copy extracted tree: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if err := checkExtractionBounds(workdir); err != nil {
		_ = os.RemoveAll(workdir)
		return err
	}
	return nil
}

// normalizeWorkdir makes the extracted tree readable from inside the scan
// container: rootless userns can't traverse or read dirs/files owned by the
// host user unless they are world-readable. Directories become 0755 and
// regular files 0644 (modes are irrelevant to the scan itself).
func normalizeWorkdir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if d.IsDir() {
			mode = 0o755
		}
		return os.Chmod(path, mode)
	})
}

// ruleSet returns an immutable snapshot of the compiled rule files, rebuilding
// them when the rules directory changes (or on first use). Callers must not
// mutate the returned slice.
func (s *Scanner) ruleSet() ([]string, string) {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	if s.rules == nil {
		// Never primed (e.g. missing rules dir): refresh so the error is
		// reported instead of a silent no-op.
		s.refreshRulesLocked()
	} else if fi, err := os.Stat(s.yaraRulesDir); err == nil && !fi.ModTime().Equal(s.dirMTime) {
		s.refreshRulesLocked()
	}
	files := make([]string, len(s.rules))
	copy(files, s.rules)
	return files, s.rulesErr
}

// refreshRulesLocked collects every .yar/.yara rule file under yaraRulesDir
// and keeps only those that compile together, so external-variable rules and
// duplicate rule names can't break the whole engine. Caller holds rulesMu.
func (s *Scanner) refreshRulesLocked() {
	s.rules = nil
	s.rulesErr = ""
	if s.yaraRulesDir == "" {
		s.rulesErr = "yara rules dir not configured"
		return
	}
	files, err := collectRuleFiles(s.yaraRulesDir)
	if err != nil {
		s.rulesErr = err.Error()
		return
	}
	if len(files) == 0 {
		s.rulesErr = "no yara rules found"
		return
	}

	// Iteratively drop files reported by the compiler until the set is valid.
	remaining := files
	for removed, round := 0, 0; round < len(files); round++ {
		out, cerr := s.compile(remaining)
		if cerr == nil {
			s.rules = remaining
			if fi, err := os.Stat(s.yaraRulesDir); err == nil {
				s.dirMTime = fi.ModTime()
			}
			if removed > 0 {
				log.Printf("yara: dropped %d rule file(s) that did not compile", removed)
			}
			return
		}
		log.Printf("yara: round %d compile failed for %d files, output=%q err=%v", round, len(remaining), out, cerr)
		offender := yaraErrorFile(cerr)
		if offender == "" {
			// Compiler blamed the ruleset but not a specific file; keep only
			// files that compile standalone and retry.
			remaining = s.standaloneRules(files)
			removed = len(files) - len(remaining)
			continue
		}
		next := remaining[:0:0]
		for _, f := range remaining {
			if filepath.Base(f) == offender {
				removed++
				continue
			}
			next = append(next, f)
		}
		remaining = next
		if len(remaining) == 0 {
			break
		}
	}

	if len(remaining) > 0 {
		s.rules = remaining
	} else {
		s.rulesErr = "yara rules could not be compiled"
	}
}

func collectRuleFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yar" || ext == ".yara" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// standaloneRules returns rule files that compile on their own.
func (s *Scanner) standaloneRules(files []string) []string {
	var good []string
	for _, f := range files {
		if _, err := s.compile([]string{f}); err == nil {
			good = append(good, f)
		}
	}
	return good
}

func (s *Scanner) compile(files []string) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no rule files")
	}
	args := append([]string{"-w"}, files...)
	args = append(args, os.DevNull)
	out, err := s.run(context.Background(), s.cmd(context.Background(), "yara", args...))
	if err != nil {
		return string(out), fmt.Errorf("yara compile: %w", err)
	}
	return string(out), nil
}

// yaraErrorFile pulls the first <file>(<line>) reference out of a yara compile
// error so we can drop exactly the rule file that broke the set.
func yaraErrorFile(compileErr error) string {
	re := regexp.MustCompile(`([A-Za-z0-9_./\\-]+\.ya?ra?)\(\d+\)`)
	if m := re.FindStringSubmatch(compileErr.Error()); len(m) > 1 {
		return filepath.Base(m[1])
	}
	return ""
}

func (s *Scanner) Quarantine(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dest := filepath.Join(s.quarantineDir, filepath.Base(path))
	if err := os.Rename(path, dest); err != nil {
		return fmt.Errorf("move to quarantine: %w", err)
	}
	// Remove all permissions
	if err := os.Chmod(dest, 0000); err != nil {
		return fmt.Errorf("chmod quarantine file: %w", err)
	}
	log.Printf("quarantined: %s -> %s", path, dest)
	return nil
}

func (s *Scanner) Delete(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.Remove(path)
}

func parseClamAVOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, ": "); idx != -1 {
			threat := strings.TrimSpace(line[idx+2:])
			if threat != "" && !strings.Contains(threat, "OK") {
				return threat
			}
		}
	}
	return "unknown threat"
}

func parseYARAOutput(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				return parts[0]
			}
		}
	}
	return "yara match"
}
