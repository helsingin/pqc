//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly)

package core

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

func lockAudit(context.Context, *os.File) error {
	return fmt.Errorf("durable file audit locking is unsupported on %s; configure another Auditor", runtime.GOOS)
}
func unlockAudit(*os.File) error { return nil }
