package scanner

import (
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanArchiveContentRealContainer is an opt-in end-to-end smoke test that
// exercises the real mutiny-scan Docker container: it drops a zip that only
// contains an EICAR payload into the download root and asserts scanYARA
// surfaces a threat from the extracted tree.
//
// Run with:  MUTINY_E2E=1 go test ./internal/scanner/ -run TestScanArchiveContentRealContainer -v
func TestScanArchiveContentRealContainer(t *testing.T) {
	if os.Getenv("MUTINY_E2E") == "" {
		t.Skip("set MUTINY_E2E=1 to run against the real mutiny-scan container")
	}
	const container = "mutiny-scan"
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", container).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Fatalf("%s not running: %v %s", container, err, out)
	}

	root := os.Getenv("MUTINY_DOWNLOAD_DIR")
	if root == "" {
		home, _ := os.UserHomeDir()
		root = filepath.Join(home, "Downloads", "Mutiny")
	}
	rules := os.Getenv("MUTINY_RULES_DIR")
	if rules == "" {
		home, _ := os.UserHomeDir()
		rules = filepath.Join(home, ".local", "share", "mutiny", "rules")
	}
	if !dirExists(root) || !dirExists(rules) {
		t.Fatalf("download root %q or rules dir %q missing", root, rules)
	}

	const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
	zipPath := filepath.Join(root, "mutiny-e2e-archive-scan.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		f.Close()
		os.Remove(zipPath)
	}()
	zw := zip.NewWriter(f)
	w, err := zw.Create("private/eicar.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(eicar)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := New("/var/run/clamav/clamd.ctl", rules, root, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.ScanContainer = container
	s.WorkRoot = root
	s.ruleSet() // recompile inside the container

	res := s.scanYARA(context.Background(), zipPath, 0)
	if res.Threat == "" {
		t.Fatalf("expected EICAR archive contents to be flagged by YARA, got %+v", res)
	}
	if res.Scanner != "yara" {
		t.Fatalf("expected yara scanner, got %+v", res)
	}
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
