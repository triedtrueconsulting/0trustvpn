//go:build !windows

package obfs

import (
	"os/exec"
	"syscall"
)

// detach puts the relay in its own process group so a Ctrl-C in the terminal
// that ran `0trust connect` does not also kill the transport the tunnel is
// now depending on.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
