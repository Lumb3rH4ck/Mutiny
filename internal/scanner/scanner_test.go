package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func testFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanUnscannedWhenNoEnginesAvailable(t *testing.T) {
	tmp := t.TempDir()
	file := testFile(t, tmp, "a.bin", "some bytes")

	s, err := New("", "", tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	res := s.ScanFile(file)

	if res.Clean {
		t.Fatalf("expected NOT clean when no engines available, got clean")
	}
	if res.Threat != "" {
		t.Fatalf("expected no threat when no engines available, got %q", res.Threat)
	}
	if res.Error == "" {
		t.Fatalf("expected an unscanned error when no engines available")
	}
}

func TestScanMissingFile(t *testing.T) {
	s, err := New("", "", t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	res := s.ScanFile(filepath.Join(t.TempDir(), "nope.bin"))
	if res.Error == "" {
		t.Fatalf("expected stat error for missing file")
	}
}

func TestScanFileStepEmitsProgressInEngineOrder(t *testing.T) {
	tmp := t.TempDir()
	file := testFile(t, tmp, "a.bin", "same bytes")

	s, err := New("", "", tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	var steps []ScanStep
	s.Progress = func(st ScanStep) { steps = append(steps, st) }

	res := s.ScanFileStep(file, ScanStep{TorrentID: "abc", Index: 3, Total: 7})

	if res.Error == "" {
		t.Fatalf("expected unscanned when no engines available")
	}
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps (one per engine), got %d", len(steps))
	}
	if steps[0].Engine != "clamav" {
		t.Fatalf("expected first step to be clamav, got %q", steps[0].Engine)
	}
	if steps[1].Engine != "yara" {
		t.Fatalf("expected second step to be yara, got %q", steps[1].Engine)
	}
	for _, st := range steps {
		if st.TorrentID != "abc" || st.Index != 3 || st.Total != 7 || st.File != file {
			t.Fatalf("step context lost: %+v", st)
		}
	}
	if got, want := steps[0].Label(), "ClamAV Scan: 3 of 7"; got != want {
		t.Fatalf("clamav label = %q, want %q", got, want)
	}
	if got, want := steps[1].Label(), "Yara Check: 3 of 7"; got != want {
		t.Fatalf("yara label = %q, want %q", got, want)
	}
}

func TestScanFileEmitsNoProgressWithoutTotal(t *testing.T) {
	tmp := t.TempDir()
	file := testFile(t, tmp, "a.bin", "same bytes")

	s, err := New("", "", tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	emitted := false
	s.Progress = func(ScanStep) { emitted = true }

	s.ScanFile(file)
	if emitted {
		t.Fatalf("ScanFile without a total must not emit progress steps")
	}
}

func TestScanSkipsOversizedFile(t *testing.T) {
	tmp := t.TempDir()
	file := testFile(t, tmp, "big.bin", "0123456789")

	// max scan 5 bytes -> file of 10 bytes is skipped
	s, err := New("", "", tmp, 5)
	if err != nil {
		t.Fatal(err)
	}
	res := s.ScanFile(file)

	if !res.Clean {
		t.Fatalf("expected oversized file to be skipped as clean")
	}
	if res.Threat == "" {
		t.Fatalf("expected skip note")
	}
}

func TestScanReportsThreatFromClamAV(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	writeStub(t, bin, "clamdscan", "#!/bin/sh\necho \"file.bin: Eicar-Test-Signature\"\nexit 1\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	file := testFile(t, tmp, "file.bin", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")
	s, err := New("/var/run/clamav/clamd.ctl", "", tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	res := s.ScanFile(file)

	if res.Clean {
		t.Fatalf("expected threat to be found")
	}
	if res.Threat != "Eicar-Test-Signature" {
		t.Fatalf("expected Eicar-Test-Signature, got %q", res.Threat)
	}
	if res.Scanner != "clamav" {
		t.Fatalf("expected clamav scanner, got %q", res.Scanner)
	}
}

func TestScanCleanWhenBothEnginesAvailable(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	writeStub(t, bin, "clamdscan", "#!/bin/sh\necho \"file.bin: OK\"\nexit 0\n")
	writeStub(t, bin, "yara", "#!/bin/sh\ncat >/dev/null\nexit 0\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	rules := filepath.Join(tmp, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "test.yar"), []byte("rule t { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}

	file := testFile(t, tmp, "file.bin", "clean bytes")
	s, err := New("/var/run/clamav/clamd.ctl", rules, tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	res := s.ScanFile(file)

	if !res.Clean {
		t.Fatalf("expected clean when both engines available, got %+v", res)
	}
}

func TestScanReportsThreatFromYARA(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	// yara prints "RuleName <file>" on a match and exits 0.
	writeStub(t, bin, "yara", "#!/bin/sh\nif [ \"$1\" = \"-w\" ]; then shift; fi\necho \"EICAR_Test_File $@\"\nexit 0\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	rules := filepath.Join(tmp, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "eicar.yar"), []byte("rule EICAR_Test_File { condition: false }"), 0o644); err != nil {
		t.Fatal(err)
	}

	file := testFile(t, tmp, "file.bin", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	s, err := New("", rules, tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	res := s.ScanFile(file)

	if res.Clean {
		t.Fatalf("expected yara threat to be found")
	}
	if res.Threat != "EICAR_Test_File" {
		t.Fatalf("expected EICAR_Test_File, got %q", res.Threat)
	}
	if res.Scanner != "yara" {
		t.Fatalf("expected yara scanner, got %q", res.Scanner)
	}
}

func TestYARAruleSetDropsBrokenFiles(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	// A yara stub that behaves like the real compiler: errors on files that
	// reference an undefined external ("filename") and compiles the rest.
	writeStub(t, bin, "yara", `#!/bin/sh
for f in "$@"; do
  [ -f "$f" ] || continue
  if grep -q "external-broken-rule" "$f"; then
    echo "error: rule \"SUSP_X\" in $(basename "$f")(1): undefined identifier \"filename\"" >&2
    exit 1
  fi
done
exit 0
`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	rules := filepath.Join(tmp, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	good := "rule GEN_Sample { meta: description = \"ok\" strings: $a = \"abc\" ascii condition: $a }\n"
	bad := "rule SUSP_X {       /* external-broken-rule */ condition: filename }\n"
	for name, body := range map[string]string{"good.yar": good, "bad.yar": bad} {
		if err := os.WriteFile(filepath.Join(rules, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	s, err := New("", rules, tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	files, errStr := s.ruleSet()
	if errStr != "" {
		t.Fatalf("unexpected rules error: %s", errStr)
	}
	if len(files) != 1 {
		t.Fatalf("expected only the good rule file to survive, got %v", files)
	}
	if filepath.Base(files[0]) != "good.yar" {
		t.Fatalf("expected good.yar to survive, got %v", files)
	}

	// And scanning is still attempted with the surviving rules — yara is the
	// only working engine here, so under the both-engines rule the file is
	// reported unscanned, not clean.
	file := testFile(t, tmp, "t.txt", "abc plain data")
	res := s.ScanFile(file)
	if res.Clean {
		t.Fatalf("expected unscanned when only yara is available, got %+v", res)
	}
	if res.Threat != "" {
		t.Fatalf("expected no threat from surviving rules, got %q", res.Threat)
	}
	if !strings.Contains(res.Error, "clamav") {
		t.Fatalf("expected error to name missing clamav, got %q", res.Error)
	}
}

func TestScanUnscannedWhenSecondaryEngineMissing(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	// Only clamdscan is available; yara is not installed here.
	writeStub(t, bin, "clamdscan", "#!/bin/sh\necho \"file.bin: OK\"\nexit 0\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	file := testFile(t, tmp, "file.bin", "clean bytes")
	// rules dir missing: yara cannot run at all.
	s, err := New("/var/run/clamav/clamd.ctl", "", tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	res := s.ScanFile(file)

	if res.Clean {
		t.Fatalf("expected unscanned when only one engine ran, got %+v", res)
	}
	if !strings.Contains(res.Error, "yara") {
		t.Fatalf("expected error to name missing yara, got %q", res.Error)
	}
}

func TestIsArchive(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"a.zip", true},
		{"a.tar", true},
		{"a.tar.gz", true},
		{"a.tgz", true},
		{"a.tar.xz", true},
		{"a.txz", true},
		{"a.bz2", true},
		{"a.zst", true},
		{"a.7z", true},
		{"a.rar", true},
		{"a.cab", true},
		{"archive.ZIP", true},
		{"nested/deep/a.lz", true},
		{"a.txt", false},
		{"a.exe", false},
		{"a.mp4", false},
		{"noext", false},
		{"a.tar.xzs", false},
	}
	for _, c := range cases {
		if got := isArchive(c.path); got != c.want {
			t.Errorf("isArchive(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestScaledTimeout verifies the effective per-file deadline scales with file
// size off a configurable base, and that zero-size / disabled bases behave.
func TestScaledTimeout(t *testing.T) {
	var s Scanner
	base := 20 * time.Minute
	s.Timeout = base

	if got := s.scaledTimeout(0); got != base {
		t.Fatalf("scaledTimeout(0) = %s, want base %s", got, base)
	}
	// A small file never earns extra budget beyond the base.
	if got, want := s.scaledTimeout(1*1024*1024), base+0*time.Second; got != want {
		t.Fatalf("scaledTimeout(1MiB) = %s, want %s", got, want)
	}
	// 100 GiB at the 32 MiB/s floor earns ~3200s of extra budget.
	want := base + time.Duration((100*1024*1024*1024)/scanRateFloor)*time.Second
	if got := s.scaledTimeout(100 * 1024 * 1024 * 1024); got != want {
		t.Fatalf("scaledTimeout(100GiB) = %s, want %s", got, want)
	}

	// Disabled base stays disabled regardless of size.
	s.Timeout = 0
	if got := s.scaledTimeout(100 * 1024 * 1024 * 1024); got != 0 {
		t.Fatalf("disabled timeout must stay 0, got %s", got)
	}
}

// TestScanTimesOutHungEngine proves a stuck engine subprocess is killed after
// the per-file Timeout instead of freezing the torrent in the scanning dir.
func TestScanTimesOutHungEngine(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	writeStub(t, bin, "yara", `#!/bin/sh
last=""
for a in "$@"; do last="$a"; done
[ "$last" = "/dev/null" ] && exit 0
sleep 30
exit 0
`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	rules := filepath.Join(tmp, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "test.yar"), []byte("rule t { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New("", rules, tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Timeout = 200 * time.Millisecond

	start := time.Now()
	res := s.ScanFile(testFile(t, tmp, "a.bin", "bytes"))

	if res.Clean {
		t.Fatalf("expected NOT clean on timeout, got clean")
	}
	if res.Error == "" || !strings.Contains(res.Error, "timed out") {
		t.Fatalf("expected a timeout error, got %q", res.Error)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("scan with 200ms timeout took %s; engine was not killed", elapsed)
	}
}

// archiveStubs returns stub bsdtar + yara binaries. The bsdtar stub extracts
// (writes) a file carrying ARCHIVE-MARKER into the -C dir; the yara stub only
// reports a hit when the marker is found inside one of its TARGET directories
// (i.e. the extracted tree), never on the raw archive bytes.
func archiveStubs(t *testing.T, bin string) {
	t.Helper()
	writeStub(t, bin, "bsdtar", `#!/bin/sh
prev=""
dir=""
for a in "$@"; do
  [ "$prev" = "-C" ] && dir="$a"
  prev="$a"
done
[ -n "$dir" ] || { echo "bsdtar: missing -C" >&2; exit 1; }
mkdir -p "$dir"
echo "ARCHIVE-MARKER zipped payload" > "$dir/extracted.bin"
exit 0
`)
	writeStub(t, bin, "yara", `#!/bin/sh
if [ "$1" = "-w" ]; then shift; fi
if [ "$1" = "-r" ]; then shift; fi
for t in "$@"; do
  if [ -d "$t" ]; then
    if grep -rl "ARCHIVE-MARKER" "$t" >/dev/null 2>&1; then
      echo "Yara_Archive_Hit payload"
      exit 0
    fi
  elif [ -f "$t" ]; then
    if grep -q "ARCHIVE-MARKER" "$t"; then
      echo "Yara_Raw_Hit payload"
      exit 0
    fi
  fi
done
exit 0
`)
}

func archiveScanner(t *testing.T, tmp, bin string) *Scanner {
	t.Helper()
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	rules := filepath.Join(tmp, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "test.yar"), []byte("rule t { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New("", rules, tmp, 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestWithinExtractionBounds verifies the zip-bomb ceilings math directly.
func TestWithinExtractionBounds(t *testing.T) {
	ok, at := withinExtractionBounds(1, 1), withinExtractionBounds(extractEntriesCap, extractBytesCap)
	if !ok || !at {
		t.Fatalf("bounds exactly at cap must pass: ok=%v at=%v", ok, at)
	}
	if withinExtractionBounds(extractEntriesCap+1, 1) {
		t.Fatal("entry count over cap must be rejected")
	}
	if withinExtractionBounds(1, extractBytesCap+1) {
		t.Fatal("byte count over cap must be rejected")
	}
}

// TestCheckExtractionBoundsRejectsPathExplosion walks a tree that exceeds the
// member-count ceiling (tiny zero-byte files, cheap to create) and ensures the
// guard rejects it.
func TestCheckExtractionBoundsRejectsPathExplosion(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < extractEntriesCap+1; i++ {
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("f%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	if err := checkExtractionBounds(dir); err == nil {
		t.Fatal("expected extraction-bounds rejection for path explosion")
	}
}

// TestCheckExtractionBoundsAcceptsSmallTree ensures a normal archive tree passes.
func TestCheckExtractionBoundsAcceptsSmallTree(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "a.bin"), make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkExtractionBounds(dir); err != nil {
		t.Fatalf("small tree must pass bounds check, got %v", err)
	}
}

// TestScanYARAChecksArchiveContents proves zipped payloads are checked: the
// marker only exists inside the extracted file, so a hit requires scanYARA to
// run bsdtar and yara -r over the extracted tree.
func TestScanYARAChecksArchiveContents(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	archiveStubs(t, bin)

	file := testFile(t, tmp, "payload.zip", "PK\x05\x06 fake zip container")
	s := archiveScanner(t, tmp, bin)

	res := s.scanYARA(context.Background(), file, 0)
	if res.Clean {
		t.Fatalf("expected archive contents to be flagged, got clean: %+v", res)
	}
	if res.Threat != "Yara_Archive_Hit" {
		t.Fatalf("expected Yara_Archive_Hit from extracted tree, got %q", res.Threat)
	}
	if res.Scanner != "yara" {
		t.Fatalf("expected yara scanner, got %q", res.Scanner)
	}
}

// TestScanYARAFallsBackToRawWhenExtractionFails verifies a broken/corrupt
// archive degrades to a raw-file scan instead of an unscanned error.
func TestScanYARAFallsBackToRawWhenExtractionFails(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	writeStub(t, bin, "bsdtar", "#!/bin/sh\necho 'bsdtar: corrupt archive' >&2\nexit 1\n")
	writeStub(t, bin, "yara", `#!/bin/sh
if [ "$1" = "-w" ]; then shift; fi
for t in "$@"; do
  if [ -f "$t" ] && grep -q "RAW-MARKER" "$t"; then
    echo "Yara_Raw_Hit payload"
    exit 0
  fi
done
exit 0
`)

	file := testFile(t, tmp, "payload.tar.gz", "RAW-MARKER raw bytes")
	s := archiveScanner(t, tmp, bin)

	res := s.scanYARA(context.Background(), file, 0)
	if res.Error != "" {
		t.Fatalf("extraction failure must not produce unscanned error, got %+v", res)
	}
	if res.Threat != "Yara_Raw_Hit" {
		t.Fatalf("expected raw fallback hit, got %+v", res)
	}
}

// TestScanYARADoesNotExtractPlainFiles guards the non-archive path: bsdtar
// must never be invoked for a file that isn't an archive.
func TestScanYARADoesNotExtractPlainFiles(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	writeStub(t, bin, "bsdtar", "#!/bin/sh\necho 'bsdtar must not be invoked' >&2\nexit 99\n")
	writeStub(t, bin, "yara", `#!/bin/sh
if [ "$1" = "-w" ]; then shift; fi
if [ "$1" = "-r" ]; then
  echo "unexpected -r on plain file" >&2
  exit 99
fi
for t in "$@"; do
  if [ -f "$t" ] && grep -q "RAW-MARKER" "$t"; then
    echo "Yara_Raw_Hit payload"
    exit 0
  fi
done
exit 0
`)

	file := testFile(t, tmp, "note.txt", "RAW-MARKER text")
	s := archiveScanner(t, tmp, bin)

	res := s.scanYARA(context.Background(), file, 0)
	if res.Threat != "Yara_Raw_Hit" {
		t.Fatalf("expected raw hit without extraction, got %+v", res)
	}
}
