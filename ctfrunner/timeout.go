package ctfrunner

import (
	"fmt"
	"strings"
)

// shellQuote 用单引号包裹，保证命令原样传给内层 bash。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// wrapTimeout 让命令在容器内由 coreutils timeout 限时：先 TERM，3 秒后 KILL，
// 作用于整个进程组，超时退出码为 124。
func wrapTimeout(command string, seconds int) string {
	return fmt.Sprintf("exec timeout -k 3 %d /bin/bash -c %s", seconds, shellQuote(command))
}
