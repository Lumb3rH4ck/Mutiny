//go:build linux

package main

import (
	"log"
	"os/exec"
	"syscall"
)

func openPathPlatform(path string) {
	cmd := exec.Command("xdg-open", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		log.Printf("open %s: %v", path, err)
	}
}
