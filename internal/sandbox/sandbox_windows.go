//go:build windows

package sandbox

import (
	"context"
	"time"
)

// Behavior analysis is not supported on Windows (strace-based sandbox is
// Linux-only). New returns nil so callers skip the sandbox path entirely.
func New(container string, timeout time.Duration) *Sandbox {
	return nil
}

// SetTrustedToolLookup is a no-op on Windows.
func SetTrustedToolLookup(fn func(string) string) {}

// IsExecutable always returns false on Windows (sandbox disabled).
func IsExecutable(path string) bool {
	return false
}

// Analyze is not supported on Windows. It returns a report indicating the
// sample was not executed.
func (s *Sandbox) Analyze(ctx context.Context, filePath string) BehaviorReport {
	return BehaviorReport{
		NotExecutedReason: "sandbox not supported on Windows",
	}
}
