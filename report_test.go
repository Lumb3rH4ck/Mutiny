package main

import (
	"strings"
	"testing"

	"mutiny/internal/scanner"
)

func TestRenderScanReport(t *testing.T) {
	lines := []reportLine{
		{Path: "Big Buck Bunny/Big Buck Bunny.mp4", Size: 276134947, Result: "clean",
			Engines: []scanner.EngineStep{
				{Name: "clamav", Result: "clean"},
				{Name: "yara", Result: "clean"},
			}},
		{Path: "Big Buck Bunny/Big Buck Bunny.en.srt", Size: 140, Result: "clean"},
		{Path: "Big Buck Bunny/poster.jpg", Size: 310380, Result: "threat", Threat: "Eicar-Test-Signature FOUND",
			Engines: []scanner.EngineStep{
				{Name: "clamav", Result: "threat", Detail: "Eicar-Test-Signature FOUND"},
				{Name: "yara", Result: "clean"},
			}},
		{Path: "Big Buck Bunny/curious.bin", Size: 99, Result: "unscanned", Reason: "yara rules dir not configured",
			Engines: []scanner.EngineStep{
				{Name: "clamav", Result: "clean"},
				{Name: "yara", Result: "unscanned", Detail: "yara rules dir not configured"},
			}},
	}

	report := renderScanReport("Big Buck Bunny", "dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c", "threats_found", true, lines)

	for _, want := range []string{
		"Mutiny scan report",
		"Torrent:     Big Buck Bunny",
		"Infohash:    dd8255ecdc7ca55fb0bbf81323d87062db1f6d1c",
		"Result:      threats_found",
		"Note:        threats were moved to the quarantine folder",
		"[THREAT]    Big Buck Bunny/poster.jpg (310380 bytes) - Eicar-Test-Signature FOUND",
		"[unscanned] Big Buck Bunny/curious.bin - yara rules dir not configured",
		"Summary: 2 clean, 1 threat, 1 unscanned",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q\n---\n%s", want, report)
		}
	}

	// Per-engine breakdown must persist each engine's pass/fail per file.
	for _, want := range []string{
		"engines: clamav clean · yara clean",
		"engines: clamav threat (Eicar-Test-Signature FOUND) · yara clean",
		"engines: clamav clean · yara unscanned (yara rules dir not configured)",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing per-engine detail %q\n---\n%s", want, report)
		}
	}
}
