//go:build linux

package updater

import (
	"fmt"
	"os"
	"syscall"
)

func clamDBDirOwnerPlatform(dir string) string {
	fi, err := os.Stat(dir)
	if err != nil {
		return "0:0"
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", st.Uid, st.Gid)
	}
	return "0:0"
}
