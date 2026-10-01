package server

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// sdNotify sends a state string to systemd's notification socket
// ($NOTIFY_SOCKET; abstract names start with '@'). It is a no-op when the
// variable is unset (not started by systemd with Type=notify). Implemented
// without dependencies (sd_notify(3) protocol: one datagram per message).
func sdNotify(state string) bool {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return false
	}
	if addr[0] != '/' && addr[0] != '@' {
		return false // vsock and other transports are not used by FileParcel units
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = c.Write([]byte(state))
	return err == nil
}

// startExtendEvery is how often ExtendStartTimeout renews its extension (a
// variable for tests). Each message extends the start timeout by three
// intervals, so one late tick does not end the start.
var startExtendEvery = 20 * time.Second

// ExtendStartTimeout keeps systemd's start timeout (TimeoutStartSec, 90 s by
// default, running until READY=1) from killing a start that is busy but
// healthy — applying a scheduled restore of a large backup, migrating the
// database: it sends EXTEND_TIMEOUT_USEC (systemd 236+; older versions
// ignore it) with status as the unit's STATUS line now and every
// startExtendEvery until stop is called or ctx ends (SIGTERM). stop waits for
// the sender, so nothing is sent after it returns: an extension sent while
// the unit stops would stretch its stop timeout instead. A no-op without
// $NOTIFY_SOCKET (not started by systemd).
func ExtendStartTimeout(ctx context.Context, status string) (stop func()) {
	if os.Getenv("NOTIFY_SOCKET") == "" {
		return func() {}
	}
	every := startExtendEvery
	msg := "EXTEND_TIMEOUT_USEC=" + strconv.FormatInt((3*every).Microseconds(), 10) + "\nSTATUS=" + status
	ctx, cancel := context.WithCancel(ctx)
	if ctx.Err() == nil {
		sdNotify(msg)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if ctx.Err() == nil {
					sdNotify(msg)
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// watchdogInterval returns half of $WATCHDOG_USEC when the watchdog is
// enabled for this process ($WATCHDOG_PID unset or equal to our pid).
func watchdogInterval() time.Duration {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	if p := os.Getenv("WATCHDOG_PID"); p != "" {
		if pid, err := strconv.Atoi(p); err != nil || pid != os.Getpid() {
			return 0
		}
	}
	return time.Duration(usec) * time.Microsecond / 2
}

// watchdog sends WATCHDOG=1 every interval while healthy() holds, until ctx
// ends. A failing health check skips the keep-alive so that systemd restarts
// a wedged server once WatchdogSec elapses.
func watchdog(ctx context.Context, interval time.Duration, healthy func(context.Context) error, onFail func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			hctx, cancel := context.WithTimeout(ctx, interval/2)
			err := healthy(hctx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					onFail(err)
				}
				continue
			}
			sdNotify("WATCHDOG=1")
		}
	}
}
