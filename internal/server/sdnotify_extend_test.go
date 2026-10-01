package server

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// ExtendStartTimeout renews systemd's start timeout while startup work
// runs, with a STATUS line, and sends nothing once stopped.
func TestExtendStartTimeout(t *testing.T) {
	sockPath := "@fp-extend-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if runtime.GOOS != "linux" {
		dir, err := shortTempDir(t)
		if err != nil {
			t.Fatal(err)
		}
		sockPath = filepath.Join(dir, "notify")
	}
	pc, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Skipf("unixgram unavailable: %v", err)
	}
	defer pc.Close()
	msgs := make(chan string, 64)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := pc.ReadFromUnix(buf)
			if err != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()
	old := startExtendEvery
	startExtendEvery = 20 * time.Millisecond
	t.Cleanup(func() { startExtendEvery = old })

	// Without NOTIFY_SOCKET it does nothing.
	t.Setenv("NOTIFY_SOCKET", "")
	ExtendStartTimeout(context.Background(), "idle")()

	t.Setenv("NOTIFY_SOCKET", sockPath)
	stop := ExtendStartTimeout(context.Background(), "Applying the scheduled restore")
	want := "EXTEND_TIMEOUT_USEC=60000\nSTATUS=Applying the scheduled restore"
	for i := 0; i < 3; i++ { // the first one at once, then renewed
		select {
		case m := <-msgs:
			if m != want {
				t.Fatalf("message %q, want %q", m, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("extension %d not sent", i+1)
		}
	}
	stop()
	stop() // idempotent
	time.Sleep(50 * time.Millisecond)
	for len(msgs) > 0 {
		<-msgs // sent before stop returned
	}
	select {
	case m := <-msgs:
		t.Fatalf("sent after stop: %q", m)
	case <-time.After(100 * time.Millisecond):
	}

	// A cancelled context (SIGTERM) ends it as well.
	ctx, cancel := context.WithCancel(context.Background())
	stop = ExtendStartTimeout(ctx, "x")
	<-msgs
	cancel()
	time.Sleep(50 * time.Millisecond)
	for len(msgs) > 0 {
		<-msgs
	}
	select {
	case m := <-msgs:
		t.Fatalf("sent after the context ended: %q", m)
	case <-time.After(100 * time.Millisecond):
	}
	stop()
}
