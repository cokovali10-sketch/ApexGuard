package idor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCollectIDs(t *testing.T) {
	body := []byte(`{
		"id": 42,
		"user_id": "alice-1",
		"order_id": 777,
		"nested": {"uuid": "abc-123", "owner_id": "o-9"},
		"items": [{"id": 5}],
		"name": "not-an-id"
	}`)
	ids := CollectIDs(body)
	want := map[string]bool{"42": true, "alice-1": true, "777": true, "abc-123": true, "o-9": true, "5": true}
	if len(ids) != len(want) {
		t.Fatalf("expected %d ids, got %d: %v", len(want), len(ids), ids)
	}
	for _, id := range ids {
		if !want[id] {
			t.Fatalf("unexpected id %q", id)
		}
	}
}

func TestCollectIDsURLPattern(t *testing.T) {
	body := []byte(`{"href": "https://api.corp.local/users/9f8e7d6c-5b4a-4321-9fed-cba987654321"}`)
	ids := CollectIDs(body)
	found := false
	for _, id := range ids {
		if id == "9f8e7d6c-5b4a-4321-9fed-cba987654321" {
			found = true
		}
	}
	if !found {
		t.Fatalf("url-extracted id missing: %v", ids)
	}
}

func TestSimilarity(t *testing.T) {
	if similarity([]byte("hello world"), []byte("hello world")) < 0.9 {
		t.Fatal("identical bodies should have high similarity")
	}
	if similarity([]byte("aaaa"), []byte("bbbb")) != 0 {
		t.Fatal("different bodies should have zero similarity")
	}
	if similarity([]byte{}, []byte("x")) != 0 {
		t.Fatal("empty input similarity must be 0")
	}
}

func TestCrossCheckDetectsLeak(t *testing.T) {
	// сервер: владелец Alice видит объект, злоумышленник Bob тоже (утечка)
	leaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/users/")
		token := r.Header.Get("Authorization")
		switch token {
		case "Bearer alice":
			fmt.Fprintf(w, `{"id":%s,"user_id":"alice","email":"alice@corp.local"}`, id)
		default:
			fmt.Fprintf(w, `{"id":%s,"user_id":"alice","email":"alice@corp.local"}`, id)
		}
	}))
	defer leaky.Close()

	d := NewDetector()
	owner := &Session{Name: "alice", Token: "alice", Client: leaky.Client(), Base: leaky.URL}
	intruder := &Session{Name: "bob", Token: "bob", Client: leaky.Client(), Base: leaky.URL}
	d.CrossCheck(owner, intruder, []string{"42", "43"}, []string{"/api/users"})

	findings := d.Findings()
	if len(findings) != 2 {
		t.Fatalf("expected 2 IDOR findings, got %d: %+v", len(findings), findings)
	}
	if findings[0].Intruder != "bob" {
		t.Fatalf("unexpected intruder: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Evidence, "alice@corp.local") {
		t.Fatalf("evidence missing personal data: %+v", findings[0])
	}
}

func TestCrossCheckNoFalsePositive(t *testing.T) {
	// корректный сервер: Bob получает 403 на чужие объекты
	secure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/users/")
		if r.Header.Get("Authorization") != "Bearer alice" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		fmt.Fprintf(w, `{"id":%s,"user_id":"alice","email":"alice@corp.local"}`, id)
	}))
	defer secure.Close()

	d := NewDetector()
	owner := &Session{Name: "alice", Token: "alice", Client: secure.Client(), Base: secure.URL}
	intruder := &Session{Name: "bob", Token: "bob", Client: secure.Client(), Base: secure.URL}
	d.CrossCheck(owner, intruder, []string{"42"}, []string{"/api/users"})

	if n := len(d.Findings()); n != 0 {
		t.Fatalf("expected no findings on secure server, got %d", n)
	}
}

func TestIsPersonalData(t *testing.T) {
	if !isPersonalData([]byte(`{"email":"a@b.c"}`)) {
		t.Fatal("email must be personal")
	}
	if isPersonalData([]byte(`{"status":"ok"}`)) {
		t.Fatal("generic payload must not be personal")
	}
}
