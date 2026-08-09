package bus

import (
	"sync"
	"testing"
	"time"

	aegisv1 "github.com/apexguard/apexguard/core/gen"
)

func ev(src aegisv1.EventSource, sev aegisv1.Severity) *aegisv1.ThreatEvent {
	return &aegisv1.ThreatEvent{Source: src, Severity: sev}
}

func TestSubscribeAndPublish(t *testing.T) {
	b := New(16, 64)
	sub := b.Subscribe(nil, aegisv1.Severity_SEVERITY_INFO)
	defer b.Unsubscribe(sub)

	b.Publish(ev(aegisv1.EventSource_EVENT_SOURCE_KERNELSHIELD, aegisv1.Severity_SEVERITY_HIGH))
	select {
	case got := <-sub.C:
		if got.GetSeverity() != aegisv1.Severity_SEVERITY_HIGH {
			t.Fatalf("unexpected severity: %v", got.GetSeverity())
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestFilterBySeverity(t *testing.T) {
	b := New(16, 64)
	sub := b.Subscribe(nil, aegisv1.Severity_SEVERITY_MEDIUM)
	defer b.Unsubscribe(sub)

	// LOW ниже порога — не должен дойти.
	b.Publish(ev(aegisv1.EventSource_EVENT_SOURCE_CORE, aegisv1.Severity_SEVERITY_LOW))
	select {
	case <-sub.C:
		t.Fatal("event below min severity delivered")
	case <-time.After(100 * time.Millisecond):
	}

	b.Publish(ev(aegisv1.EventSource_EVENT_SOURCE_CORE, aegisv1.Severity_SEVERITY_CRITICAL))
	select {
	case <-sub.C:
	case <-time.After(time.Second):
		t.Fatal("critical event not delivered")
	}
}

func TestFilterBySource(t *testing.T) {
	b := New(16, 64)
	sub := b.Subscribe([]aegisv1.EventSource{aegisv1.EventSource_EVENT_SOURCE_PULSEFUZZ}, aegisv1.Severity_SEVERITY_INFO)
	defer b.Unsubscribe(sub)

	b.Publish(ev(aegisv1.EventSource_EVENT_SOURCE_KERNELSHIELD, aegisv1.Severity_SEVERITY_CRITICAL))
	select {
	case <-sub.C:
		t.Fatal("event from other source delivered")
	case <-time.After(100 * time.Millisecond):
	}
	b.Publish(ev(aegisv1.EventSource_EVENT_SOURCE_PULSEFUZZ, aegisv1.Severity_SEVERITY_INFO))
	select {
	case <-sub.C:
	case <-time.After(time.Second):
		t.Fatal("pulsefuzz event not delivered")
	}
}

func TestUnsubscribeClosesChannel(t *testing.T) {
	b := New(16, 64)
	sub := b.Subscribe(nil, aegisv1.Severity_SEVERITY_INFO)
	b.Unsubscribe(sub)
	if _, ok := <-sub.C; ok {
		t.Fatal("channel not closed after unsubscribe")
	}
}

func TestRecentReplay(t *testing.T) {
	b := New(16, 5)
	for i := 0; i < 10; i++ {
		b.Publish(ev(aegisv1.EventSource_EVENT_SOURCE_CORE, aegisv1.Severity_SEVERITY_INFO))
	}
	recent := b.Recent(5)
	if len(recent) != 5 {
		t.Fatalf("expected 5 recent, got %d", len(recent))
	}
	if b.SubscriberCount() != 0 {
		t.Fatalf("expected 0 subscribers, got %d", b.SubscriberCount())
	}
}

func TestAirGapBroadcast(t *testing.T) {
	b := New(4, 64)
	b.SetAirGap(true, "test")
	engaged, reason := b.AirGapState()
	if !engaged || reason != "test" {
		t.Fatalf("airgap state wrong: %v %q", engaged, reason)
	}

	// команда должна дойти по каналу с id
	cmd := <-b.Commands()
	if cmd.GetCommandId() == "" {
		t.Fatal("command missing id")
	}
	if cmd.GetAirGap() == nil {
		t.Fatal("expected airgap action")
	}

	// без консьюмера BroadcastCommand не должен блокироваться (drop-oldest)
	for i := 0; i < b.cmdBuffer+10; i++ {
		b.BroadcastCommand(&aegisv1.Command{})
	}
	if n := len(b.Commands()); n > b.cmdBuffer {
		t.Fatalf("command buffer overflow: %d", n)
	}
}

func TestConcurrentPublish(t *testing.T) {
	b := New(64, 1024)
	sub := b.Subscribe(nil, aegisv1.Severity_SEVERITY_INFO)
	defer b.Unsubscribe(sub)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				b.Publish(ev(aegisv1.EventSource_EVENT_SOURCE_HEXEYE, aegisv1.Severity_SEVERITY_MEDIUM))
			}
		}()
	}
	wg.Wait()

	// читаем, пока не увидим все (подписчик может дропнуть при переполнении буфера 8192)
	deadline := time.After(2 * time.Second)
	count := 0
	for {
		select {
		case <-sub.C:
			count++
		case <-deadline:
			if count == 0 {
				t.Fatal("no events received under concurrency")
			}
			return
		}
	}
}
