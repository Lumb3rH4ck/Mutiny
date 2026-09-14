//go:build windows

package main

func setUmask() {
	// Windows has no umask; file ACLs are managed differently.
}
