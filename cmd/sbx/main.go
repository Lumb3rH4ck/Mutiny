//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"mutiny/internal/sandbox"
)

func main() {
	timeout := flag.Duration("timeout", 5*time.Minute, "max runtime per sample")
	image := flag.String("image", "mutiny-scan", "sandbox container image")
	asJSON := flag.Bool("json", false, "emit the full behavior report as JSON")
	showTrace := flag.Bool("trace", false, "include the raw strace output")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: sandbox [flags] <file>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	file := flag.Arg(0)

	sb := sandbox.New(*image, *timeout)
	report := sb.Analyze(context.Background(), file)

	if *asJSON {
		out := struct {
			Verdict  string                `json:"verdict"`
			Summary  string                `json:"summary"`
			FileOps  []sandbox.FileOp      `json:"file_ops"`
			Execs    []sandbox.ExecAttempt `json:"exec_attempts"`
			Nets     []sandbox.NetAttempt  `json:"net_attempts"`
			Error    string                `json:"error,omitempty"`
			RawTrace string                `json:"raw_trace,omitempty"`
		}{
			Verdict:  report.Verdict,
			Summary:  report.Summary,
			FileOps:  report.FileOps,
			Execs:    report.ExecAttempts,
			Nets:     report.NetAttempts,
			Error:    report.Error,
			RawTrace: report.RawTrace,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}

	fmt.Printf("verdict: %s\n", report.Verdict)
	fmt.Printf("summary: %s\n", report.Summary)
	if report.Error != "" {
		fmt.Printf("error:   %s\n", report.Error)
	}
	if *showTrace && report.RawTrace != "" {
		fmt.Println("trace:")
		fmt.Println(report.RawTrace)
	}
}