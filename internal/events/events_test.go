package events

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func recv(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("channel closed")
		}
		return e
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	return Event{}
}

func empty(t *testing.T, ch <-chan Event) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("unexpected event %+v", e)
	default:
	}
}

func TestTopicFiltering(t *testing.T) {
	b := New()
	all, c1 := b.Subscribe()
	jobs, c2 := b.Subscribe("job.*")
	settings, c3 := b.Subscribe(TopicSettingsChanged, TopicNetworkChanged)
	defer c1()
	defer c2()
	defer c3()

	b.Publish(Event{Topic: TopicJobDone, UserID: "usr_1", Data: 1})
	b.Publish(Event{Topic: TopicSettingsChanged, Data: 2})
	b.Publish(Event{Topic: "jobs.other"}) // must not match "job.*"

	if e := recv(t, all); e.Topic != TopicJobDone || e.UserID != "usr_1" || e.Data != 1 {
		t.Fatalf("%+v", e)
	}
	if e := recv(t, all); e.Topic != TopicSettingsChanged {
		t.Fatalf("%+v", e)
	}
	if e := recv(t, all); e.Topic != "jobs.other" {
		t.Fatalf("%+v", e)
	}
	if e := recv(t, jobs); e.Topic != TopicJobDone {
		t.Fatalf("%+v", e)
	}
	empty(t, jobs)
	if e := recv(t, settings); e.Topic != TopicSettingsChanged {
		t.Fatalf("%+v", e)
	}
	empty(t, settings)
	if !Match("*", "x") || !Match("a.*", "a.b") || Match("a.*", "ab.c") || Match("a.b", "a.c") {
		t.Fatal("Match")
	}
}

func TestDropOldest(t *testing.T) {
	b := New()
	ch, cancel := b.Subscribe()
	defer cancel()
	total := BufferSize + 50
	for i := 0; i < total; i++ {
		b.Publish(Event{Topic: "t", Data: i})
	}
	if len(ch) != BufferSize {
		t.Fatalf("buffered %d", len(ch))
	}
	first := recv(t, ch)
	if first.Data != 50 {
		t.Fatalf("oldest kept = %v, want 50", first.Data)
	}
	var last Event
	for len(ch) > 0 {
		last = <-ch
	}
	if last.Data != total-1 {
		t.Fatalf("newest = %v", last.Data)
	}
}

func TestUnsubscribeAndClose(t *testing.T) {
	b := New()
	ch, cancel := b.Subscribe()
	if b.Subscribers() != 1 {
		t.Fatal("Subscribers")
	}
	cancel()
	cancel() // idempotent
	if _, ok := <-ch; ok {
		t.Fatal("channel not closed after cancel")
	}
	b.Publish(Event{Topic: "x"}) // no panic
	ch2, cancel2 := b.Subscribe("x")
	b.Close()
	b.Close()
	if _, ok := <-ch2; ok {
		t.Fatal("channel not closed after Close")
	}
	cancel2() // after close: no panic
	b.Publish(Event{Topic: "x"})
	ch3, _ := b.Subscribe()
	if _, ok := <-ch3; ok {
		t.Fatal("subscribe after close must return a closed channel")
	}
}

func TestConcurrentPublish(t *testing.T) {
	b := New()
	ch, cancel := b.Subscribe()
	var wg sync.WaitGroup
	for p := 0; p < 8; p++ {
		wg.Go(func() {
			for i := 0; i < 1000; i++ {
				b.Publish(Event{Topic: fmt.Sprintf("t.%d", p)})
			}
		})
	}
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	wg.Wait()
	cancel()
	<-done
}
