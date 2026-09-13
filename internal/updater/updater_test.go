package updater

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestUpdateRulesPullsGitRepo verifies that a git-based rules directory is
// refreshed with new rules when the remote gains commits.
func TestUpdateRulesPullsGitRepo(t *testing.T) {
	base := t.TempDir()
	remote := filepath.Join(base, "remote")

	// Bare remote with an initial rule, then clone it twice: "work" is the
	// upstream author, rulesDir is what mutiny checks out.
	mkdirAll(t, remote)
	run(t, "git", "init", "--bare", "--initial-branch=main", remote)

	work := filepath.Join(base, "work")
	run(t, "git", "clone", remote, work)
	writeFile(t, filepath.Join(work, "custom.yar"), "rule R1 { condition: true }\n")
	run(t, "git", "-C", work, "add", "custom.yar")
	commit(t, work, "init")
	run(t, "git", "-C", work, "push", "-u", "origin", "main")

	rulesDir := filepath.Join(base, "rules")
	run(t, "git", "clone", remote, rulesDir)

	// Upstream gains a new rule.
	writeFile(t, filepath.Join(work, "custom.yar"), "rule R1 { condition: true }\nrule R2 { condition: true }\n")
	run(t, "git", "-C", work, "add", "custom.yar")
	commit(t, work, "add rule")
	run(t, "git", "-C", work, "push")

	// Local clone is behind.
	blob := readFile(t, filepath.Join(rulesDir, "custom.yar"))
	if strings.Contains(blob, "R2") {
		t.Fatal("precondition: local rules must be behind the remote")
	}

	u := New(Config{RulesDir: rulesDir})
	u.updateRules()

	after := readFile(t, filepath.Join(rulesDir, "custom.yar"))
	if !strings.Contains(after, "R2") {
		t.Fatalf("rules dir was not updated by git pull:\n%s", after)
	}
}

func commit(t *testing.T, dir, msg string) {
	t.Helper()
	run(t, "git", "-C", dir, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", msg)
}

// TestUpdateRulesSkipsNonRepo verifies a non-git rules dir is skipped without
// error (no panic, no command leaks).
func TestUpdateRulesSkipsNonRepo(t *testing.T) {
	rulesDir := t.TempDir()
	writeFile(t, filepath.Join(rulesDir, "custom.yar"), "rule R1 { condition: true }\n")
	u := New(Config{RulesDir: rulesDir})
	u.updateRules() // must not panic or hang
}

// TestUpdateRulesFetchesURL verifies a non-git rules dir with a yara_rules_url
// is refreshed from the downloaded archive, and that a pre-existing local rule
// file (custom.yar) survives the merge.
func TestUpdateRulesFetchesURL(t *testing.T) {
	rulesDir := t.TempDir()
	writeFile(t, filepath.Join(rulesDir, "custom.yar"), "rule Local { condition: true }\n")

	var served []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(served)
	}))
	defer srv.Close()

	served = rulesZip(t, map[string]string{
		"gen_quietteam.yar": "rule QuietTeam { condition: true }\n",
	})

	u := New(Config{RulesDir: rulesDir, YaraRulesURL: srv.URL + "/rules.zip"})
	u.updateRules()

	if got := readFile(t, filepath.Join(rulesDir, "gen_quietteam.yar")); !strings.Contains(got, "QuietTeam") {
		t.Fatalf("downloaded rule not installed:\n%s", got)
	}
	if got := readFile(t, filepath.Join(rulesDir, "custom.yar")); !strings.Contains(got, "Local") {
		t.Fatalf("local custom rule was clobbered by the update:\n%s", got)
	}
}

// TestExtractZipRejectsTraversal verifies the zip-slip guard refuses archives
// that try to write outside the extraction target.
func TestExtractZipRejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("../evil.yar")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("rule Evil { condition: true }\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if err := extractRules(buf.Bytes(), "zip", dest); err == nil {
		t.Fatal("extractRules accepted a traversal archive")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "evil.yar")); err == nil {
		t.Fatal("traversal archive wrote a file outside the target")
	}
}

// rulesZip builds an in-memory zip with the given filename->content mapping.
func rulesZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestUpdateRulesRefusesOnPinMismatch verifies an explicit yara_rules_sha256
// pin is enforced: a different archive is refused, keeping the local rules dir
// untouched.
func TestUpdateRulesRefusesOnPinMismatch(t *testing.T) {
	rulesDir := t.TempDir()
	served := rulesZip(t, map[string]string{"gen_pin.yar": "rule Pin { condition: true }\n"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(served)
	}))
	defer srv.Close()

	wrongPin := strings.Repeat("0", 64)
	u := New(Config{RulesDir: rulesDir, YaraRulesURL: srv.URL + "/rules.zip", RulesSHA256: wrongPin})
	u.updateRules()

	if _, err := os.Stat(filepath.Join(rulesDir, "gen_pin.yar")); err == nil {
		t.Fatal("archive installed despite sha256 pin mismatch")
	}
}

// TestUpdateRulesInstallsOnPinMatch verifies a matching pin installs.
func TestUpdateRulesInstallsOnPinMatch(t *testing.T) {
	rulesDir := t.TempDir()
	served := rulesZip(t, map[string]string{"gen_pin.yar": "rule Pin { condition: true }\n"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(served)
	}))
	defer srv.Close()

	pin := fmt.Sprintf("%x", sha256.Sum256(served))
	u := New(Config{RulesDir: rulesDir, YaraRulesURL: srv.URL + "/rules.zip", RulesSHA256: pin})
	u.updateRules()

	if _, err := os.Stat(filepath.Join(rulesDir, "gen_pin.yar")); err != nil {
		t.Fatalf("archive with matching pin was not installed: %v", err)
	}
}

// TestGitHubReleaseURLMatch locks the URL forms the digest resolver accepts.
func TestGitHubReleaseURLMatch(t *testing.T) {
	m := githubLatestRe.FindStringSubmatch("https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip")
	if m == nil || m[1] != "YARAHQ" || m[2] != "yara-forge" || m[3] != "yara-forge-rules-core.zip" {
		t.Fatalf("latest release URL not recognized: %v", m)
	}
	m = githubTaggedRe.FindStringSubmatch("https://github.com/YARAHQ/yara-forge/releases/download/20260906/yara-forge-rules-core.zip")
	if m == nil || m[1] != "YARAHQ" || m[2] != "yara-forge" || m[3] != "20260906" || m[4] != "yara-forge-rules-core.zip" {
		t.Fatalf("tagged release URL not recognized: %v", m)
	}
	if githubLatestRe.MatchString("https://example.com/files/rules.zip") {
		t.Fatal("non-github URL wrongly treated as a github release URL")
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
