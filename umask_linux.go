//go:build linux

package main

import "syscall"

func setUmask() {
	syscall.Umask(0o077)
}
