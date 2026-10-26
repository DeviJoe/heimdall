package activity

import (
	"fmt"
	"os"
	"syscall"
)

func fileSource(info os.FileInfo) string {
	stat := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
}
