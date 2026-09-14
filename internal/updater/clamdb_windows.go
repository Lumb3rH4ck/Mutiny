//go:build windows

package updater

func clamDBDirOwnerPlatform(dir string) string {
	// Windows Docker Desktop handles uid/gid mapping automatically; return
	// root as the safe default.
	return "0:0"
}
