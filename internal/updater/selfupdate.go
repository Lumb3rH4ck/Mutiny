package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// githubRepo identifies the upstream release source.
const githubRepo = "Lumb3rH4ck/Mutiny"

// githubAsset describes a downloadable release asset.
type githubAsset struct {
	Name        string `json:"name"`
	Size        int    `json:"size"`
	URL         string `json:"url"`
	ContentType string `json:"content_type"`
}

// githubRelease describes the subset of the GitHub release API response we need.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// SelfUpdate checks for a newer release, downloads and installs it, replacing
// the running binary. Returns true if an update was applied (caller should
// then exit and let the user restart).
func SelfUpdate(currentVersion string) (bool, error) {
	release, err := fetchLatestRelease()
	if err != nil {
		return false, fmt.Errorf("check for updates: %w", err)
	}

	latest := strings.TrimSpace(release.TagName)
	if strings.HasPrefix(latest, "v") {
		latest = latest[1:]
	}
	current := strings.TrimPrefix(currentVersion, "v")

	if !isNewer(current, latest) {
		log.Printf("updater: already on latest version (%s)", currentVersion)
		return false, nil
	}

	log.Printf("updater: updating from %s to %s", currentVersion, release.TagName)

	asset := selectAsset(release.Assets)
	if asset == nil {
		return false, fmt.Errorf("no release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	expectedDigest := assetDigest(asset.Name, release)

	tmpDir, err := os.MkdirTemp("", "mutiny-selfupdate-*")
	if err != nil {
		return false, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, asset.Name)
	if err := downloadAsset(asset, archivePath); err != nil {
		return false, fmt.Errorf("download: %w", err)
	}

	if expectedDigest != "" {
		actualDigest, err := fileSHA256(archivePath)
		if err != nil {
			return false, fmt.Errorf("checksum: %w", err)
		}
		if !strings.EqualFold(actualDigest, expectedDigest) {
			return false, fmt.Errorf("sha256 mismatch: want %s got %s", expectedDigest, actualDigest)
		}
		log.Printf("updater: checksum verified (%s)", actualDigest[:16])
	}

	exePath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("resolve executable: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return false, fmt.Errorf("resolve symlink: %w", err)
	}

	newBinary := filepath.Join(tmpDir, "mutiny")
	if err := extractBinary(archivePath, newBinary); err != nil {
		return false, fmt.Errorf("extract: %w", err)
	}

	if err := os.Chmod(newBinary, 0755); err != nil {
		return false, fmt.Errorf("chmod: %w", err)
	}

	// Write to a sibling temp file first, then atomically rename into place.
	// Direct overwrite of a running binary is blocked on some platforms.
	sibling := exePath + ".new"
	if err := copyFile(newBinary, sibling); err != nil {
		return false, fmt.Errorf("stage new binary: %w", err)
	}
	if err := os.Rename(sibling, exePath); err != nil {
		os.Remove(sibling)
		return false, fmt.Errorf("install new binary: %w", err)
	}

	log.Printf("updater: updated %s -> %s (restart to apply)", currentVersion, release.TagName)
	return true, nil
}

func fetchLatestRelease() (*githubRelease, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mutiny-selfupdate/1.0")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API returned %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// assetNamePattern matches the release asset for the current platform.
// Release assets follow: mutiny_<version>_<os>_<arch>.tar.gz
var assetNamePattern = regexp.MustCompile(`^mutiny_[^_]+_` + runtime.GOOS + `_` + goarch() + `\.tar\.gz$`)

func selectAsset(assets []githubAsset) *githubAsset {
	for i := range assets {
		if assetNamePattern.MatchString(assets[i].Name) {
			return &assets[i]
		}
	}
	return nil
}

// goarch normalises GOARCH to the release naming convention (amd64 / arm64).
func goarch() string {
	switch runtime.GOARCH {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

// assetDigest returns the expected SHA-256 for an asset. The GitHub release
// API doesn't include per-asset digests in the JSON response, so this returns
// empty (download installed unverified). The sha256sums.txt asset in the
// release could be fetched for verification in a future pass.
func assetDigest(assetName string, rel *githubRelease) string {
	_ = rel
	return ""
}

func downloadAsset(asset *githubAsset, dest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mutiny-selfupdate/1.0")
	req.Header.Set("Accept", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	r := io.LimitReader(resp.Body, 2<<30) // 2 GiB cap
	if _, err := io.Copy(f, r); err != nil {
		return err
	}
	return nil
}

func extractBinary(archivePath, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(hdr.Name) != "mutiny" {
			continue
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, 2<<30)); err != nil {
			out.Close()
			return err
		}
		out.Close()
		return nil
	}
	return fmt.Errorf("mutiny binary not found in archive")
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// isNewer reports whether latest is a newer semver than current. The special
// value "dev" is always considered older than any tagged release.
func isNewer(current, latest string) bool {
	if current == "dev" || current == "" {
		return true
	}
	cur := parseSemver(current)
	lat := parseSemver(latest)
	if lat.major != cur.major {
		return lat.major > cur.major
	}
	if lat.minor != cur.minor {
		return lat.minor > cur.minor
	}
	return lat.patch > cur.patch
}

type semver struct {
	major, minor, patch int
}

func parseSemver(s string) semver {
	var v semver
	parts := strings.Split(s, ".")
	if len(parts) >= 1 {
		fmt.Sscanf(parts[0], "%d", &v.major)
	}
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &v.minor)
	}
	if len(parts) >= 3 {
		fmt.Sscanf(parts[2], "%d", &v.patch)
	}
	return v
}
