package mutator_test

import (
	"fmt"
	"testing"

	"apexguard/pulsefuzz/internal/mutator"
)

func TestMutateJSON(t *testing.T) {
	m := mutator.New(mutator.ModeBoundary|mutator.ModeSQLi|mutator.ModeSSTI|mutator.ModeIDOR, 1)
	payload := map[string]any{
		"user_id": 5,
		"name":    "alice",
		"order":   map[string]any{"total": 100.0},
	}
	results := m.MutateJSON(payload)
	fmt.Printf("generated %d mutations\n", len(results))
	if len(results) == 0 {
		t.Fatal("no mutations generated")
	}
	for i, r := range results[:3] {
		fmt.Printf("  [%d] %v\n", i, r)
	}
}
