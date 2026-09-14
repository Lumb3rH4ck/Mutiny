//go:build windows

package main

import (
	"log"
	"os/exec"
)

func openPathPlatform(path string) {
	cmd := exec.Command("cmd", "/c", "start", "", path)
	if err := cmd.Start(); err != nil {
		log.Printf("open %s: %v", path, err)
	}
}
