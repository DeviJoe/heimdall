//go:build !linux && !freebsd

package activity

import (
	"os"
	"strconv"
)

func fileSource(info os.FileInfo) string {
	return info.Name() + ":" + strconv.FormatInt(info.ModTime().UnixNano(), 10)
}
