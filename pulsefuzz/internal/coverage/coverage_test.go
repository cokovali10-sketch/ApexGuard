package coverage

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSignatureDeterministic(t *testing.T) {
	// порядок ключей и 100.0 vs 100 не должны влиять на хэш
	a := SignatureOf(200, []byte(`{"name":"x","balance":100.0,"nested":{"b":1,"a":2}}`))
	b := SignatureOf(200, []byte(`{"balance":100,"nested":{"a":2,"b":1},"name":"x"}`))
	if a != b {
		t.Fatalf("signatures differ: %+v vs %+v", a, b)
	}
}

func TestSignatureStatusMatters(t *testing.T) {
	a := SignatureOf(200, []byte(`{"ok":true}`))
	b := SignatureOf(500, []byte(`{"ok":true}`))
	if a == b {
		t.Fatal("status must be part of signature")
	}
}

func TestObserveNewCoverage(t *testing.T) {
	c := NewCorpus()
	if !c.Observe("GET", "/users", SignatureOf(200, []byte(`[]`)), 0) {
		t.Fatal("first observation should be new coverage")
	}
	if c.Observe("GET", "/users", SignatureOf(200, []byte(`[]`)), 0) {
		t.Fatal("identical observation is not new")
	}
	if !c.Observe("GET", "/users", SignatureOf(404, []byte(`{"err":"x"}`)), 0) {
		t.Fatal("new signature should be new coverage")
	}
	if c.GraphDump()["GET /users"] != 3 {
		t.Fatalf("expected 3 hits, got %d", c.GraphDump()["GET /users"])
	}
}

func TestTimingAnomaly(t *testing.T) {
	c := NewCorpus()
	c.Observe("GET", "/slow", SignatureOf(200, []byte(`{}`)), 10*time.Millisecond)
	if c.TimingAnomaly("GET", "/slow", 40*time.Millisecond) {
		t.Fatal("4x is under 5x threshold")
	}
	if !c.TimingAnomaly("GET", "/slow", 60*time.Millisecond) {
		t.Fatal("6x should be an anomaly")
	}
	if c.TimingAnomaly("GET", "/unknown", 60*time.Millisecond) {
		t.Fatal("unknown endpoint has no baseline")
	}
}

func TestRecordTransition(t *testing.T) {
	c := NewCorpus()
	c.Observe("GET", "/a", SignatureOf(200, []byte(`1`)), 0)
	c.RecordTransition("GET", "/a", "POST", "/b")
	c.RecordTransition("GET", "/a", "POST", "/b")
	c.mu.RLock()
	n := c.graph["GET /a"]
	c.mu.RUnlock()
	if n.Transitions["POST /b"] != 2 {
		t.Fatalf("expected 2 transitions, got %d", n.Transitions["POST /b"])
	}
}

func TestSeedsEnergy(t *testing.T) {
	c := NewCorpus()
	c.AddSeed(Input{ID: "low", Score: 1})
	c.AddSeed(Input{ID: "high", Score: 5})
	c.BumpSeed(1)
	seeds := c.InterestingSeeds()
	if seeds[0].ID != "high" || seeds[0].Covered != 1 {
		t.Fatalf("expected high first with covered=1, got %+v", seeds[0])
	}
}

func TestJSONCanonicalization(t *testing.T) {
	var v any
	if err := json.Unmarshal([]byte(`{"a":1,"b":[3,2,1]}`), &v); err != nil {
		t.Fatal(err)
	}
	canon, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(canon) != `{"a":1,"b":[3,2,1]}` {
		t.Fatalf("unexpected canonical: %s", canon)
	}
}
