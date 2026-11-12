package atlas

import (
	"testing"
)

func TestAtlas_New(t *testing.T) {
	a := New()
	
	if len(a.Agents) == 0 {
		t.Fatal("expected agents to be loaded, got 0")
	}

	t.Logf("Loaded %d agents", len(a.Agents))
	
	expectedAgents := []string{"Cursor", "Claude Desktop", "Claude CLI", "Codex"}
	found := make(map[string]bool)
	
	for _, agent := range a.Agents {
		found[agent.Name] = true
		if len(agent.Locations) == 0 {
			t.Errorf("agent %s has no locations", agent.Name)
		}
	}

	for _, expected := range expectedAgents {
		if !found[expected] {
			t.Errorf("expected agent %s not found", expected)
		}
	}
}

func TestAtlas_GetAgentLocations(t *testing.T) {
	a := New()
	
	homeDir := "/home/testuser"
	locations, err := a.GetAgentLocations(homeDir)
	if err != nil {
		t.Fatalf("GetAgentLocations() error = %v", err)
	}

	if len(locations) == 0 {
		t.Fatal("expected locations, got 0")
	}

	t.Logf("Got %d total locations", len(locations))

	for _, loc := range locations[:5] {
		t.Logf("  location: %s", loc)
	}
}
