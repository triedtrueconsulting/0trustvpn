package obfs

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// KeyEnv is the environment variable the relay subprocess reads its key
// from. Never an argument: `ps` shows arguments to every account on the
// machine, and on a shared desktop that is every other user.
const KeyEnv = "ZTV_OBFS_KEY"

// FreeLoopbackPort finds a UDP port on loopback that is free right now.
//
// There is an unavoidable race between choosing the port and the relay
// binding it. It is small and the failure is loud — the relay fails to
// start and connect says so — which is better than the alternative of
// having the relay pick and then trying to discover its choice.
func FreeLoopbackPort() (int, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port, nil
}

// Spawn starts a detached relay process using this same executable, and
// returns its pid.
//
// It has to outlive `0trust connect`, which writes a config, brings the
// tunnel up and exits. A relay running inside that process would die with
// it and take the tunnel's transport with it — the tunnel would stay up,
// hold the default route, and carry nothing, which is the exact failure the
// handshake check exists to catch. So it is a child process recorded in
// state and stopped by `0trust disconnect`.
func Spawn(localPort int, server, target, key string) (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("obfs: locate self: %w", err)
	}
	cmd := exec.Command(self, "relay",
		"--listen", "127.0.0.1:"+strconv.Itoa(localPort),
		"--server", server,
		"--target", target)
	cmd.Env = append(os.Environ(), KeyEnv+"="+key)
	// The relay's own diagnostics go to the journal or the console the user
	// started from; it never writes a file, because what it would have to
	// write about is which addresses a customer is talking to.
	cmd.Stdout, cmd.Stderr = nil, nil
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("obfs: start relay: %w", err)
	}
	// Release the child so it is not left a zombie when this process exits.
	go func() { _ = cmd.Wait() }()
	return cmd.Process.Pid, nil
}

// Stop ends a relay started by Spawn. A pid that is gone, or belongs to
// something else by now, is not an error worth failing a disconnect over:
// the goal is that no relay of ours is running, and if ours already exited
// that goal is met.
func Stop(pid int) error {
	if pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if runtime.GOOS == "windows" {
		return p.Kill()
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return nil
	}
	// Give it a moment to close its sockets, then insist.
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		if err := p.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
	}
	return p.Kill()
}

// Running reports whether a pid recorded in state still refers to a live
// process. It cannot prove that process is OUR relay — a pid can be reused —
// so callers must treat it as a hint and not as authorization to kill.
func Running(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return p.Signal(syscall.Signal(0)) == nil
}
