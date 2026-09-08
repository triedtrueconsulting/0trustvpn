//go:build windows

package obfs

import (
	"os/exec"
	"syscall"
)

// detach runs the relay without a console window. Windows has no process
// groups in the POSIX sense; CREATE_NEW_PROCESS_GROUP is the equivalent
// protection from the parent console's Ctrl-C.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000200 | 0x08000000, // NEW_PROCESS_GROUP | NO_WINDOW
	}
}
