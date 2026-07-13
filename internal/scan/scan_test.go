package scan

import "testing"

type fakeScanner struct{ name string }

func (f fakeScanner) Name() string                   { return f.name }
func (f fakeScanner) Scan(string) ([]Finding, error) { return nil, nil }

func TestRegistryDeterministicOrder(t *testing.T) {
	// Reset the package registry for the test (tests run in one process).
	regMu.Lock()
	registry = map[string]Scanner{}
	regMu.Unlock()

	Register(fakeScanner{name: "zeta"})
	Register(fakeScanner{name: "alpha"})
	Register(fakeScanner{name: "mid"})
	Register(nil)                   // ignored
	Register(fakeScanner{name: ""}) // ignored

	got := All()
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("All() returned %d scanners, want %d", len(got), len(want))
	}
	for i, s := range got {
		if s.Name() != want[i] {
			t.Errorf("All()[%d] = %q, want %q", i, s.Name(), want[i])
		}
	}

	// Re-registering a name replaces, not duplicates.
	Register(fakeScanner{name: "alpha"})
	if n := len(All()); n != 3 {
		t.Errorf("after re-register, len(All()) = %d, want 3", n)
	}
}
