// Package bus — in-memory event router AegisBus.
// Fan-out pub/sub для ThreatEvent + ретрансляция команд агентам + AirGap state.
package bus

import (
	"sync"

	aegisv1 "github.com/apexguard/apexguard/core/gen"
	"github.com/google/uuid"
)

// Subscriber — канал одного потребителя событий.
type Subscriber struct {
	C   chan *aegisv1.ThreatEvent
	id  uint64
	src map[string]bool // фильтр по source (пустой = все)
	min aegisv1.Severity
}

// Bus — центральная шина событий и команд.
type Bus struct {
	mu          sync.RWMutex
	subs        map[uint64]*Subscriber
	nextSubID   uint64
	recent      []*aegisv1.ThreatEvent // ring для replay (последние N)
	recentCap   int
	recentIdx   int

	// команды агентам (WatchCommands): один широковещательный канал
	cmdCh       chan *aegisv1.Command
	cmdBuffer   int

	// состояние Panic Mode
	airgap      bool
	airgapReason string

	// метрики
	EventCount uint64
	DropCount  uint64
}

func New(cmdBuffer int, recentCap int) *Bus {
	return &Bus{
		subs:      make(map[uint64]*Subscriber),
		recent:    make([]*aegisv1.ThreatEvent, 0, recentCap),
		recentCap: recentCap,
		cmdCh:     make(chan *aegisv1.Command, cmdBuffer),
		cmdBuffer: cmdBuffer,
	}
}

// Subscribe регистрирует потребителя; minSeverity фильтрует, sources — по source.
func (b *Bus) Subscribe(sources []aegisv1.EventSource, minSeverity aegisv1.Severity) *Subscriber {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSubID++
	src := map[string]bool{}
	for _, s := range sources {
		src[s.String()] = true
	}
	s := &Subscriber{
		C:   make(chan *aegisv1.ThreatEvent, 8192),
		id:  b.nextSubID,
		src: src,
		min: minSeverity,
	}
	b.subs[s.id] = s
	return s
}

func (b *Bus) Unsubscribe(s *Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subs, s.id)
	close(s.C)
}

// Publish рассылает событие всем подписчикам (non-blocking, drop при переполнении).
func (b *Bus) Publish(ev *aegisv1.ThreatEvent) {
	b.mu.Lock()
	// ring последних событий
	if len(b.recent) < b.recentCap {
		b.recent = append(b.recent, ev)
	} else {
		b.recent[b.recentIdx] = ev
		b.recentIdx = (b.recentIdx + 1) % b.recentCap
	}
	for _, s := range b.subs {
		if !s.src[ev.GetSource().String()] && len(s.src) > 0 {
			continue
		}
		if ev.GetSeverity().Number() < s.min.Number() {
			continue
		}
		select {
		case s.C <- ev:
		default:
			b.DropCount++
		}
	}
	b.EventCount++
	b.mu.Unlock()
}

// Recent возвращает последние события (для replay при подключении консоли).
func (b *Bus) Recent(n int) []*aegisv1.ThreatEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()
	start := len(b.recent) - n
	if start < 0 {
		start = 0
	}
	out := make([]*aegisv1.ThreatEvent, 0, len(b.recent)-start)
	for i := start; i < len(b.recent); i++ {
		out = append(out, b.recent[i])
	}
	return out
}

// BroadcastCommand отправляет команду всем подключённым агентам.
func (b *Bus) BroadcastCommand(cmd *aegisv1.Command) {
	if cmd.CommandId == "" {
		cmd.CommandId = uuid.NewString()
	}
	select {
	case b.cmdCh <- cmd:
	default:
		// переполнение буфера команд — сбрасываем старые, чтобы не блокировать
		select {
		case <-b.cmdCh:
		default:
		}
		select {
		case b.cmdCh <- cmd:
		default:
		}
	}
}

// Commands возвращает канал команд для WatchCommands-стрима.
func (b *Bus) Commands() <-chan *aegisv1.Command { return b.cmdCh }

// SetAirGap переключает Panic Mode и рассылает команду всем агентам.
func (b *Bus) SetAirGap(engage bool, reason string) {
	b.mu.Lock()
	b.airgap = engage
	b.airgapReason = reason
	b.mu.Unlock()
	b.BroadcastCommand(&aegisv1.Command{
		Action: &aegisv1.Command_AirGap{
			AirGap: &aegisv1.AirGapRequest{Engage: engage, Reason: reason},
		},
	})
}

func (b *Bus) AirGapState() (bool, string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.airgap, b.airgapReason
}

// Stats — для /metrics.
func (b *Bus) Stats() (events uint64, drops uint64) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.EventCount, b.DropCount
}

// SubscriberCount — число активных подписчиков (WS/gRPC).
func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// RecentAll возвращает все события в replay-кольце (для диагностики).
func (b *Bus) RecentAll() []*aegisv1.ThreatEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Recent(len(b.recent))
}
