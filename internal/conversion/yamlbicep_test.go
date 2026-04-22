package conversion

import (
	"testing"

	"github.com/tentacle-conv/internal/model"
)

func TestYamlToBicep(t *testing.T) {
	a := model.Analytic{
		Name:           "Files_with_double_extensions",
		Severity:       "Medium",
		Description:    "Detects double extension files",
		Query:          "DeviceProcessEvents | where FileName endswith \".pdf.exe\"",
		QueryFrequency: "PT20M",
		QueryPeriod:    "PT20M",
		Mitre: []model.Mitre{
			{
				Tactics:    []string{"DefenseEvasion", "InitialAccess"},
				Techniques: []string{"T1036"},
			},
		},
		EntityMapping: []model.Entities{
			{
				EntityType: "Host",
				FieldMapping: []model.Fieldmapping{
					{Identifier: "FullName", ColumnName: "HostCustomEntity"},
				},
			},
		},
	}

	result := yamlToBicep(a)

	t.Run("sets name and kind", func(t *testing.T) {
		if result.Name != "Files_with_double_extensions" {
			t.Errorf("Name = %q, want Files_with_double_extensions", result.Name)
		}
		if result.Kind != "Scheduled" {
			t.Errorf("Kind = %q, want Scheduled", result.Kind)
		}
	})

	t.Run("maps properties correctly", func(t *testing.T) {
		p := result.Properties
		if p.DisplayName != "Files_with_double_extensions" {
			t.Errorf("DisplayName = %q, want Files_with_double_extensions", p.DisplayName)
		}
		if p.Description != "Detects double extension files" {
			t.Errorf("Description = %q, want 'Detects double extension files'", p.Description)
		}
		if p.Severity != "Medium" {
			t.Errorf("Severity = %q, want Medium", p.Severity)
		}
		if p.Query != "DeviceProcessEvents | where FileName endswith \".pdf.exe\"" {
			t.Errorf("Query mismatch")
		}
		if p.QueryFrequency != "PT20M" {
			t.Errorf("QueryFrequency = %q, want PT20M", p.QueryFrequency)
		}
		if p.QueryPeriod != "PT20M" {
			t.Errorf("QueryPeriod = %q, want PT20M", p.QueryPeriod)
		}
	})

	t.Run("sets defaults", func(t *testing.T) {
		p := result.Properties
		if p.Enabled != true {
			t.Error("Enabled should be true")
		}
		if p.TriggerOperator != "GreaterThan" {
			t.Errorf("TriggerOperator = %q, want GreaterThan", p.TriggerOperator)
		}
		if p.TriggerThreshold != 0 {
			t.Errorf("TriggerThreshold = %d, want 0", p.TriggerThreshold)
		}
		if p.SuppressionEnabled != false {
			t.Error("SuppressionEnabled should be false")
		}
		if p.SuppressionDuration != "PT5H" {
			t.Errorf("SuppressionDuration = %q, want PT5H", p.SuppressionDuration)
		}
	})

	t.Run("extracts MITRE data", func(t *testing.T) {
		p := result.Properties
		expectedTactics := []string{"DefenseEvasion", "InitialAccess"}
		expectedTechniques := []string{"T1036"}

		if len(p.Tactics) != len(expectedTactics) {
			t.Errorf("Tactics length = %d, want %d", len(p.Tactics), len(expectedTactics))
		}
		if len(p.Techniques) != len(expectedTechniques) {
			t.Errorf("Techniques length = %d, want %d", len(p.Techniques), len(expectedTechniques))
		}
		for i, tactic := range p.Tactics {
			if tactic != expectedTactics[i] {
				t.Errorf("Tactics[%d] = %q, want %q", i, tactic, expectedTactics[i])
			}
		}
		for i, tech := range p.Techniques {
			if tech != expectedTechniques[i] {
				t.Errorf("Techniques[%d] = %q, want %q", i, tech, expectedTechniques[i])
			}
		}
	})

	t.Run("sets event grouping", func(t *testing.T) {
		if result.Properties.EventGroupingSettings.AggregationKind != "AlertPerResult" {
			t.Errorf("AggregationKind = %q, want AlertPerResult", result.Properties.EventGroupingSettings.AggregationKind)
		}
	})
}