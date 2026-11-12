package atlas

import (
	_ "embed"
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed agents.yaml
var agentsData []byte

type Atlas struct {
	Agents []Agent `yaml:"agents"`
}

type Agent struct {
	Name      string   `yaml:"name"`
	Locations []string `yaml:"locations"`
}

func New() *Atlas {
	var atlas Atlas
	if err := yaml.Unmarshal(agentsData, &atlas); err != nil {
		panic(fmt.Sprintf("failed to parse embedded agents.yaml: %v", err))
	}
	return &atlas
}

func (a *Atlas) GetAgentLocations(homeDir string) ([]string, error) {
	var locations []string
	
	for _, agent := range a.Agents {
		for _, loc := range agent.Locations {
			expanded := filepath.Join(homeDir, loc)
			locations = append(locations, expanded)
		}
	}
	
	return locations, nil
}
