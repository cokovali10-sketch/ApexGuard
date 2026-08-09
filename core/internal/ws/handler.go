// Package ws — WebSocket-мост AegisBus → ApexConsole.
// Протокол: JSON ThreatEvent/SystemMetric (зеркалит proto), replay последних
// событий при подключении, фильтры через query-параметры (?source=&min_sev=).
package ws

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	aegisv1 "github.com/apexguard/apexguard/core/gen"
	"github.com/apexguard/apexguard/core/internal/bus"
	"github.com/coder/websocket"
	"github.com/rs/zerolog/log"
)

type Metrics struct {
	Eps       float64 // событий в секунду (вычисляется в main)
	LatencyMs float64
}

// Handler создаёт http.Handler для /ws/events.
// Защита: проверка Origin (CSWSH), лимит на число одновременных соединений.
func Handler(b *bus.Bus, metrics *Metrics, maxConns int) http.Handler {
	var active int32
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !sameOrigin(r, origin) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if atomic.AddInt32(&active, 1) > int32(maxConns) {
			atomic.AddInt32(&active, -1)
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}
		defer atomic.AddInt32(&active, -1)

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusInternalError, "closing")

		// фильтры из query
		sources := parseSources(r.URL.Query().Get("source"))
		minSev := parseSeverity(r.URL.Query().Get("min_sev"))
		sub := b.Subscribe(sources, minSev)
		defer b.Unsubscribe(sub)

		// replay
		ctx := r.Context()
		for _, ev := range b.Recent(200) {
			if !matchFilter(ev, sources, minSev) {
				continue
			}
			send(ctx, c, ev)
		}

		// метрики-пульс
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-sub.C:
				if !ok {
					return
				}
				if err := send(ctx, c, ev); err != nil {
					log.Debug().Err(err).Msg("ws send failed")
					return
				}
			case <-ticker.C:
				sendMetric(ctx, c, metrics)
			}
		}
	})
}

func send(ctx context.Context, c *websocket.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, data)
}

func sendMetric(ctx context.Context, c *websocket.Conn, m *Metrics) {
	msg := map[string]any{
		"host_id":        "apexcore",
		"event_rate_eps": m.Eps,
		"latency_ms":     m.LatencyMs,
		"ts":             time.Now().UTC(),
	}
	data, _ := json.Marshal(msg)
	_ = c.Write(ctx, websocket.MessageText, data)
}

// sameOrigin разрешает запрос, если Origin совпадает с Host (или отсутствует).
// Предотвращает Cross-Site WebSocket Hijacking.
func sameOrigin(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := r.Host
	// сравниваем port-агностично
	if u.Hostname() == "" {
		return false
	}
	if strings.EqualFold(u.Hostname(), stripPort(host)) {
		return true
	}
	// localhost/dev-fallback
	return u.Hostname() == "localhost" && stripPort(host) == "localhost"
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func parseSources(s string) []aegisv1.EventSource {
	if s == "" {
		return nil
	}
	var out []aegisv1.EventSource
	for _, name := range strings.Split(s, ",") {
		if v, ok := aegisv1.EventSource_value[strings.TrimSpace(name)]; ok {
			out = append(out, aegisv1.EventSource(v))
		}
	}
	return out
}

func parseSeverity(s string) aegisv1.Severity {
	if s == "" {
		return aegisv1.Severity_SEVERITY_INFO
	}
	if v, ok := aegisv1.Severity_value[s]; ok {
		return aegisv1.Severity(v)
	}
	return aegisv1.Severity_SEVERITY_INFO
}

func matchFilter(ev *aegisv1.ThreatEvent, sources []aegisv1.EventSource, min aegisv1.Severity) bool {
	if len(sources) > 0 {
		found := false
		for _, s := range sources {
			if ev.GetSource() == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return ev.GetSeverity().Number() >= min.Number()
}
