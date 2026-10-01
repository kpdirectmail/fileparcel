package mdns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fileparcel/internal/core"
)

// dnssdStopGrace is how long a dns-sd child gets to exit after SIGTERM.
const dnssdStopGrace = 2 * time.Second

// dnssdBackend publishes through macOS mDNSResponder by supervising a
// `dns-sd -P` child (DESIGN §10.5): the proxy registration announces
// <name>.local → <lan-ip> and the _https._tcp service. Using dns-sd avoids the
// Local Network privacy prompt a process opening UDP 5353 would trigger.
// The child is killed on unpublish; if it exits on its own the supervisor
// restarts it with backoff (reported as an error state).
type dnssdBackend struct {
	log  *slog.Logger
	emit func(backendEvent)
	cmd  string // "dns-sd" (tests use a fake script)

	mu  sync.Mutex
	cur *dnssdChild
}

type dnssdChild struct {
	cmd     *exec.Cmd
	gen     uint64
	stopped chan struct{} // closed by kill: the exit is intentional
	exited  chan struct{} // closed when the child has been reaped

	// instRenamed records whether this publication's DNS-SD instance name
	// already carries a " (n)" suffix; see supervise for what it decides.
	instRenamed bool
}

func newDNSSDBackend(log *slog.Logger, emit func(backendEvent)) *dnssdBackend {
	return &dnssdBackend{log: log, emit: emit, cmd: "dns-sd"}
}

func (b *dnssdBackend) kind() string { return BackendDNSSD }

// dnssdArgs builds `dns-sd -P <instance> _https._tcp local <port> <host>.local <ip> path=/ fp=1`.
// dns-sd proxies exactly one address: the first IPv4 (else IPv6) of p.
func dnssdArgs(p publication) ([]string, error) {
	addrs := p.allAddrs()
	if len(addrs) == 0 {
		return nil, errors.New("no address to publish")
	}
	args := []string{"-P", p.Instance, ServiceType, "local", strconv.Itoa(p.Port), p.FQDN(), addrs[0].String()}
	return append(args, p.TXT...), nil
}

// dnssdConflict is what classifyDNSSDLine returns for a conflict line that
// does not say which name is taken (see supervise).
const dnssdConflict = "conflict"

// classifyDNSSDLine maps a line of dns-sd output to a state ("" = none).
//
// dns-sd reports kDNSServiceErr_NameConflict as "Got a reply for record
// <host>.local: Name in use, please choose another" for the host A/AAAA
// record of -P (registered Unique: a host collision) or "Got a reply for
// service <instance>…: Name in use, …" for the service, and then exits with
// status 255. "Name conflict" / -65548 are accepted as unattributed
// fallbacks (dnssdConflict).
func classifyDNSSDLine(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "name now registered and active"):
		return core.MDNSPublished
	case strings.Contains(l, "name in use"), strings.Contains(l, "name conflict"), strings.Contains(l, "-65548"):
		switch {
		case strings.Contains(l, "reply for record"):
			return core.MDNSCollision
		case strings.Contains(l, "reply for service"):
			return stateInstanceCollision
		}
		return dnssdConflict
	}
	return ""
}

func (b *dnssdBackend) publish(ctx context.Context, gen uint64, p publication) error {
	args, err := dnssdArgs(p)
	if err != nil {
		return err
	}
	path, err := exec.LookPath(b.cmd)
	if err != nil {
		return fmt.Errorf("dns-sd not found: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.killLocked()
	// The child stays in FileParcel's process group: if FileParcel dies
	// without stopping it (SIGKILL, a fatal error), launchd's cleanup of the
	// job's process group reaps it instead of leaving an orphan advertising
	// stale records until reboot.
	cmd := exec.Command(path, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting dns-sd: %w", err)
	}
	child := &dnssdChild{cmd: cmd, gen: gen, stopped: make(chan struct{}), exited: make(chan struct{}),
		instRenamed: instanceRenamed(p.Instance)}
	b.cur = child
	go b.supervise(child, stdout)
	return nil
}

// supervise reads the child's output, reports state changes and reaps it.
//
// One `dns-sd -P` registers both the host name and the service instance.
// dns-sd registers the service without kDNSServiceFlagsNoAutoRename, so
// mDNSResponder renames a clashing instance by itself; the conflict it does
// report is the host record's ("Got a reply for record <host>.local: Name in
// use"), which renames the host (core.MDNSCollision). A "reply for service"
// conflict renames only the instance, keeping <name>.local — the leaf SANs,
// the URLs and the WebAuthn RP ID. A conflict line that names neither
// (dnssdConflict) is first *assumed* to be the instance's, and only a
// publication whose instance has already been renamed renames the host.
func (b *dnssdBackend) supervise(c *dnssdChild, out io.Reader) {
	defer close(c.exited)
	sc := bufio.NewScanner(io.LimitReader(out, 1<<20))
	collided := false
	for sc.Scan() {
		line := sc.Text()
		b.log.Debug("mdns: dns-sd", "line", line)
		switch st := classifyDNSSDLine(line); st {
		case core.MDNSPublished:
			b.emit(backendEvent{gen: c.gen, state: st})
		case core.MDNSCollision, stateInstanceCollision, dnssdConflict:
			if !collided {
				collided = true
				if st == dnssdConflict {
					st = core.MDNSCollision
					if !c.instRenamed {
						st = stateInstanceCollision
					}
				}
				b.emit(backendEvent{gen: c.gen, state: st})
			}
		}
	}
	_, _ = io.Copy(io.Discard, out)
	err := c.cmd.Wait()
	select {
	case <-c.stopped:
		return // killed on purpose
	default:
	}
	if collided {
		return
	}
	if err == nil {
		err = errors.New("exited")
	}
	b.emit(backendEvent{gen: c.gen, state: core.MDNSError, err: fmt.Errorf("dns-sd %w", err)})
}

// killLocked stops the current child (SIGTERM, SIGKILL after a grace
// period) and waits for it. dns-sd has no children of its own, so the process
// is signalled directly; os.Process refuses to signal one already reaped, so
// a recycled PID is never hit. b.mu is held.
func (b *dnssdBackend) killLocked() {
	c := b.cur
	if c == nil {
		return
	}
	b.cur = nil
	close(c.stopped)
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-c.exited:
			return
		case <-time.After(dnssdStopGrace):
		}
		_ = c.cmd.Process.Kill()
	}
	<-c.exited
}

func (b *dnssdBackend) unpublish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.killLocked()
}

func (b *dnssdBackend) close() error {
	b.unpublish()
	return nil
}
