package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// maxRulesArchiveBytes caps a downloaded rules archive so a stale, huge, or
// hostile download cannot fill the disk. The archive is fully buffered before
// extraction, so the cap also bounds memory.
const maxRulesArchiveBytes = 512 * 1024 * 1024 // 512 MiB

// Config carries the update settings needed to refresh both scan engines.
type Config struct {
	// RulesDir is the YARA rules directory (e.g. ~/.local/share/mutiny/rules).
	// When it is a git working tree, rules are refreshed with git pull;
	// otherwise they are refreshed from YaraRulesURL when set.
	RulesDir string
	// YaraRulesURL, when RulesDir is not a git working tree, is the URL of a
	// .zip / .tar.gz rules archive to fetch. New rule files are merged into
	// RulesDir (local files not present in the archive are preserved). Empty
	// skips the yara refresh for non-repo rules dirs.
	YaraRulesURL string
	// RulesSHA256 is an explicit sha256 pin for the downloaded archive
	// (hex, lowercase). When set, the download is refused unless it matches,
	// even if the URL is not a pin-able GitHub release. For GitHub release
	// download URLs with no explicit pin, the digest published in the GitHub
	// release metadata is verified against the download instead (so weekly
	// rule releases don't hard-break). Downloads from other sources with no
	// pin are installed unverified with a loud log.
	RulesSHA256 string
	// ScanContainer is the docker container running clamav+yara. When set,
	// freshclam runs inside it; otherwise the host freshclam binary is used.
	ScanContainer string
	// ClamDBDir is the ClamAV signature directory shared with the scan
	// container (bind-mounted at the same path). freshclam runs as its owner
	// so the container needs neither root-setuid nor extra capabilities.
	// Defaults to /var/lib/clamav.
	ClamDBDir string
}

// Updater refreshes scan rules and signatures on a timer without ever
// disrupting in-flight scans: the scanner revalidates/recompiles rule files on
// next use, and per-file clamscan runs read the signatures dir fresh each time,
// so swapping files underneath a scan is safe.
type Updater struct {
	cfg Config
	mu  sync.Mutex
}

func New(cfg Config) *Updater {
	return &Updater{cfg: cfg}
}

// Run performs an update pass immediately, then every interval until ctx is
// cancelled. Failures are logged, never fatal, and never block scanning.
func (u *Updater) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 7 * 24 * time.Hour
	}
	u.UpdateAll()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.UpdateAll()
		}
	}
}

// UpdateAll refreshes rules and signatures. Serialized with a mutex so a
// manual trigger can never overlap the timer pass.
func (u *Updater) UpdateAll() {
	u.mu.Lock()
	defer u.mu.Unlock()
	log.Printf("updater: engine + rule refresh starting")
	u.updateRules()
	u.updateClamAV()
}

// updateRules keeps the YARA rules directory current: git pull when it is a
// working tree, otherwise a fetch from YaraRulesURL (a non-repo dir is merged
// in place so locally-added rules such as custom.yar survive an update).
// Missing sources are skipped silently.
func (u *Updater) updateRules() {
	if u.cfg.RulesDir == "" {
		return
	}
	if out, err := exec.Command("git", "-C", u.cfg.RulesDir, "rev-parse", "--is-inside-work-tree").CombinedOutput(); err == nil &&
		strings.TrimSpace(string(out)) == "true" {
		u.gitPull()
		return
	}
	if u.cfg.YaraRulesURL != "" {
		u.fetchRules()
		return
	}
	log.Printf("updater: rules dir %s is not a git repo and no yara_rules_url is set, skipping yara refresh", u.cfg.RulesDir)
}

// gitPull refreshes a git working-tree rules dir.
func (u *Updater) gitPull() {
	out, err := exec.Command("git", "-C", u.cfg.RulesDir, "pull", "--ff-only", "--quiet").CombinedOutput()
	if err != nil {
		log.Printf("updater: yara rules pull failed: %v: %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("updater: yara rules refreshed in %s", u.cfg.RulesDir)
}

// fetchRules downloads a rules archive from YaraRulesURL, extracts it into a
// temp dir, and merges the rule files into RulesDir. The download is capped,
// the temp dir samples the hostile-archive guards (no traversal, regular files
// only), and the merge preserves any local files the archive does not contain.
func (u *Updater) fetchRules() {
	url := u.cfg.YaraRulesURL

	dlCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, url, nil)
	if err != nil {
		log.Printf("updater: build yara download request: %v", err)
		return
	}
	req.Header.Set("User-Agent", "mutiny/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("updater: download %s: %v", url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("updater: download %s: status %d", url, resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRulesArchiveBytes+1))
	if err != nil {
		log.Printf("updater: read %s: %v", url, err)
		return
	}
	if int64(len(body)) > maxRulesArchiveBytes {
		log.Printf("updater: rules archive from %s exceeds %d bytes, not installing", url, maxRulesArchiveBytes)
		return
	}
	if err := u.verifyRulesDigest(url, body); err != nil {
		log.Printf("updater: yara rules checksum verification FAILED, not installing: %v", err)
		return
	}
	kind := archiveKind(url, body)
	if kind == "" {
		log.Printf("updater: rules archive from %s is not a recognized zip/tar.gz", url)
		return
	}

	// Extract into a temp dir on the same filesystem as the rules dir so the
	// merge below is a copy (never a destructive swap of the live dir).
	tmp, err := os.MkdirTemp(filepath.Dir(u.cfg.RulesDir), ".mutiny-rules-in-*")
	if err != nil {
		log.Printf("updater: rules temp dir: %v", err)
		return
	}
	defer os.RemoveAll(tmp)

	if err := extractRules(body, kind, tmp); err != nil {
		log.Printf("updater: extract rules from %s: %v", url, err)
		return
	}
	if !hasRuleFiles(tmp) {
		log.Printf("updater: archive from %s contained no .yar/.yara rule files, not installing", url)
		return
	}

	if err := os.MkdirAll(u.cfg.RulesDir, 0700); err != nil {
		log.Printf("updater: create rules dir %s: %v", u.cfg.RulesDir, err)
		return
	}
	if err := mergeRules(tmp, u.cfg.RulesDir); err != nil {
		log.Printf("updater: merge rules %s -> %s: %v", tmp, u.cfg.RulesDir, err)
		return
	}
	log.Printf("updater: yara rules merged from %s into %s (verification happens on the next yara compile pass)", url, u.cfg.RulesDir)
}

// mergeRules copies every file under src into dst, preserving the relative
// layout. Files that already exist are overwritten; files in dst outside src
// are left untouched, so local custom rules survive updates.
func mergeRules(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0644)
	})
}

// hasRuleFiles reports whether dir contains at least one .yar/.yara file.
func hasRuleFiles(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && (strings.HasSuffix(strings.ToLower(d.Name()), ".yar") ||
			strings.HasSuffix(strings.ToLower(d.Name()), ".yara")) {
			found = true
			return filepath.SkipDir
		}
		return nil
	})
	return found
}

// extractRules unpacks a zip or gzipped-tar archive into dest, refusing
// absolute paths, ".." traversal, and any non-regular entries (symlinks,
// devices, hardlinks).
func extractRules(data []byte, kind, dest string) error {
	switch kind {
	case "zip":
		return extractZip(data, dest)
	case "tar.gz":
		return extractTarGz(data, dest)
	default:
		return fmt.Errorf("unsupported archive kind %q", kind)
	}
}

func archiveKind(url string, data []byte) string {
	lower := strings.ToLower(url)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar.gz"
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("PK\x03\x04")) {
		return "zip"
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return "tar.gz"
	}
	return ""
}

func extractZip(data []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 || f.Mode()&os.ModeDevice != 0 || f.Mode()&os.ModeNamedPipe != 0 {
			continue
		}
		rel := filepath.Clean(f.Name)
		if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("rules archive entry escapes target: %q", f.Name)
		}
		target := filepath.Join(dest, rel)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(filepath.Separator)) {
			return fmt.Errorf("rules archive entry escapes target: %q", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			rc.Close()
			return err
		}
		_, cerr := io.Copy(out, io.LimitReader(rc, maxRulesArchiveBytes+1))
		rc.Close()
		if e := out.Close(); cerr == nil {
			cerr = e
		}
		if cerr != nil {
			return cerr
		}
	}
	return nil
}

func extractTarGz(data []byte, dest string) error {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(filepath.Join(dest, hdr.Name), 0700); err != nil {
				return err
			}
			continue
		case tar.TypeReg, tar.TypeRegA:
			// regular file: handled below
		default:
			// symlinks, links, devices, fifos: never materialize.
			continue
		}
		rel := filepath.Clean(hdr.Name)
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("rules archive entry escapes target: %q", hdr.Name)
		}
		target := filepath.Join(dest, rel)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(filepath.Separator)) {
			return fmt.Errorf("rules archive entry escapes target: %q", hdr.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		_, cerr := io.Copy(out, io.LimitReader(tr, maxRulesArchiveBytes+1))
		if e := out.Close(); cerr == nil {
			cerr = e
		}
		if cerr != nil {
			return cerr
		}
	}
}

// verifyRulesDigest checks the downloaded archive against a configured pin or,
// for GitHub release URLs, against the digest the GitHub release metadata
// publishes for the same asset. Mismatches are fatal to the update pass.
func (u *Updater) verifyRulesDigest(url string, body []byte) error {
	actual := fmt.Sprintf("%x", sha256.Sum256(body))

	expected := strings.ToLower(strings.TrimSpace(u.cfg.RulesSHA256))
	if expected == "" {
		digest, err := githubReleaseDigest(url)
		if err != nil {
			log.Printf("updater: installing yara rules from %s WITHOUT checksum verification (set yara_rules_sha256 to pin a specific archive): %v", url, err)
			return nil
		}
		expected = digest
	}

	if actual != expected {
		return fmt.Errorf("sha256 mismatch for %s: want %s got %s", url, expected, actual)
	}
	log.Printf("updater: yara rules archive sha256 verified (%s)", actual)
	return nil
}

// githubReleaseRe matches github.com release download URLs. The latest-variant
// resolves its tag through the releases/latest API; the tagged variant uses the
// tag directly. Groups: owner, repo, [tag], asset.
var (
	githubLatestRe = regexp.MustCompile(`^https?://github\.com/([^/]+)/([^/]+)/releases/latest/download/([^/]+)$`)
	githubTaggedRe = regexp.MustCompile(`^https?://github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/([^/]+)$`)
)

// githubReleaseDigest returns the lowercase hex sha256 that GitHub's release
// metadata publishes for the asset at the given release download URL, or an
// error when the URL is not a github.com release download URL or the metadata
// has no usable digest.
func githubReleaseDigest(url string) (string, error) {
	var owner, repo, asset, apiURL string
	if m := githubLatestRe.FindStringSubmatch(url); m != nil {
		owner, repo, asset = m[1], m[2], m[3]
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	} else if m := githubTaggedRe.FindStringSubmatch(url); m != nil {
		owner, repo, asset = m[1], m[2], m[4]
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, m[3])
	} else {
		return "", fmt.Errorf("%s is not a github.com release download url", url)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mutiny/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api %s returned status %d", apiURL, resp.StatusCode)
	}

	var rel struct {
		Assets []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&rel); err != nil {
		return "", err
	}
	for _, a := range rel.Assets {
		if a.Name != asset {
			continue
		}
		digest := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(a.Digest, "sha256:")))
		if len(digest) == 64 && isHex(digest) {
			return digest, nil
		}
		return "", fmt.Errorf("release metadata has no usable sha256 digest for %s", asset)
	}
	return "", fmt.Errorf("asset %q not found in github release metadata", asset)
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// updateClamAV refreshes ClamAV signatures: freshclam inside the scan container
// (container mode) or the host freshclam binary (local mode). Local runs
// typically require root and may fail gracefully.
func (u *Updater) updateClamAV() {
	if u.cfg.ScanContainer != "" {
		dbDir := u.cfg.ClamDBDir
		if dbDir == "" {
			dbDir = "/var/lib/clamav"
		}
		// The scan container drops ALL capabilities, so freshclam running as
		// root cannot setuid/initgroups to the 'clamav' user and aborts before
		// ever downloading. Run it as the owner of the shared DB dir instead:
		// no privilege switch is attempted (uid != 0) and the datadir's owner
		// can write it. Log to a tmpfs path (the rootfs is read-only and the
		// default /var/log/clamav/freshclam.log is not writable from the exec).
		owner := clamDBDirOwner(dbDir)
		out, err := exec.Command("docker", "exec", "-u", owner,
			u.cfg.ScanContainer, "freshclam",
			"--datadir="+dbDir, "--log=/tmp/freshclam.log").CombinedOutput()
		if err != nil {
			log.Printf("updater: freshclam in container %s failed: %v: %s",
				u.cfg.ScanContainer, err, strings.TrimSpace(string(out)))
			return
		}
		log.Printf("updater: clamav signatures refreshed in container %s", u.cfg.ScanContainer)
		return
	}
	out, err := exec.Command("freshclam").CombinedOutput()
	if err != nil {
		log.Printf("updater: freshclam failed: %v: %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("updater: clamav signatures refreshed")
}

// clamDBDirOwner returns the uid:gid of the ClamAV database directory so the
// container-side freshclam can be exec'd as the non-root user that owns it.
// Falls back to root when the directory cannot be stat'd.
func clamDBDirOwner(dir string) string {
	return clamDBDirOwnerPlatform(dir)
}
