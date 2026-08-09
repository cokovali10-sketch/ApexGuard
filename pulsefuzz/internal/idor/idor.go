// PulseFuzz — IDOR (Insecure Direct Object Reference) детектор.
//
// Принцип: перекрёстная проверка двух сессий.
//   1. Сессия A создаёт/получает объекты → извлекаем идентификаторы из ответов.
//   2. Тот же запрос с сессией B (другой пользователь).
//   3. Если B получает данные A (не 401/403/404 и не пустой ресурс) → IDOR.
//
// Идентификаторы извлекаются по имени ключа (id/user_id/order_id/uuid/...)
// и по shape (uuid, числовой, base64url).
package idor

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"sync"
)

var idKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)["'](id|user_?id|account_?id|order_?id|uuid|object_?id|owner_?id)["']\s*:\s*"([^"]+)"`),
	regexp.MustCompile(`(?i)["'](id|user_?id|account_?id|order_?id|uuid|object_?id|owner_?id)["']\s*:\s*(\d+)`),
	regexp.MustCompile(`(?i)/(users|orders|accounts|documents|items)/([0-9a-f-]{8,})`),
}

var denyStatus = map[int]bool{401: true, 403: true, 404: true, 405: true}

type Session struct {
	Name  string
	Token string
	Client *http.Client
	Base  string
}

type Finding struct {
	URL          string
	ObjectID     string
	OwnerSession string
	Intruder     string
	Status       int
	Evidence     string
}

type Detector struct {
	mu       sync.Mutex
	findings []Finding
}

func NewDetector() *Detector { return &Detector{} }

// Findings возвращает накопленные находки.
func (d *Detector) Findings() []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Finding, len(d.findings))
	copy(out, d.findings)
	return out
}

// CollectIDs извлекает идентификаторы объектов из тела ответа A.
func CollectIDs(body []byte) []string {
	var ids []string
	seen := map[string]bool{}
	put := func(id string) {
		if id != "" && !seen[id] && id != "null" {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, rx := range idKeyPatterns {
		for _, m := range rx.FindAllSubmatch(body, -1) {
			put(string(m[2]))
		}
	}
	// JSON-путь по ключу
	var doc map[string]any
	if json.Unmarshal(body, &doc) == nil {
		walkIDs(doc, put)
	}
	return ids
}

func walkIDs(v any, put func(string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if isIDKey(k) {
				switch id := val.(type) {
				case string:
					put(id)
				case float64:
					put(strconv.FormatFloat(id, 'f', -1, 64))
				}
			}
			walkIDs(val, put)
		}
	case []any:
		for _, e := range t {
			walkIDs(e, put)
		}
	}
}

func isIDKey(k string) bool {
	switch k {
	case "id", "user_id", "account_id", "order_id", "uuid", "object_id", "owner_id", "userId", "UID":
		return true
	}
	return false
}

// CrossCheck: пробует все собранные ID через сессию intruder.
// По результатам запускает probe на каждый подозрительный endpoint.
func (d *Detector) CrossCheck(owner *Session, intruder *Session, ids []string, probePaths []string) {
	// Извлекаем пути-шаблоны из probePaths: подставляем ID
	for _, path := range probePaths {
		for _, id := range ids {
			url := owner.Base + path + "/" + id
			ownerResp := d.get(owner, url)
			if ownerResp == nil {
				continue
			}
			ownerBody := readAll(ownerResp)

			intResp := d.get(intruder, url)
			if intResp == nil {
				continue
			}
			intBody := readAll(intResp)
			intStatus := intResp.StatusCode

			// Аномалия: intruder не должен видеть чужие данные.
			if !denyStatus[intStatus] && isPersonalData(ownerBody) {
				// Сравниваем «отпечаток»: если тела почти совпадают → реальная утечка.
				if bytes.Contains(intBody, ownerBody) || similarity(intBody, ownerBody) > 0.8 {
					d.mu.Lock()
					d.findings = append(d.findings, Finding{
						URL: url, ObjectID: id,
						OwnerSession: owner.Name, Intruder: intruder.Name,
						Status: intStatus, Evidence: truncate(string(intBody), 200),
					})
					d.mu.Unlock()
				}
			}
		}
	}
}

func (d *Detector) get(s *Session, url string) *http.Response {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("X-Api-Key", s.Token)
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil
	}
	return resp
}

func readAll(r *http.Response) []byte {
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return b
}

func isPersonalData(body []byte) bool {
	lower := bytes.ToLower(body)
	for _, marker := range []string{"email", "phone", "address", "card", "password", "passport", "first_name", "last_name"} {
		if bytes.Contains(lower, []byte(marker)) {
			return true
		}
	}
	return false
}

// similarity — грубая метрика перекрытия (Jaccard по чанкам 4 байта).
func similarity(a, b []byte) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	setA := map[string]bool{}
	for i := 0; i+4 <= len(a); i += 4 {
		setA[string(a[i:i+4])] = true
	}
	inter := 0
	total := len(setA)
	seen := map[string]bool{}
	for i := 0; i+4 <= len(b); i += 4 {
		chunk := string(b[i : i+4])
		if !seen[chunk] {
			seen[chunk] = true
			if setA[chunk] {
				inter++
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(inter) / float64(total)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
