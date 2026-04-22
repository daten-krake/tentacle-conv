package conversion

import (
	"testing"

	"github.com/tentacle-conv/internal/model"
)

func TestYamlToJson(t *testing.T) {
	a := model.Analytic{
		Name:           "External_guest_sign_in",
		Severity:       "Medium",
		Description:    "Detects external guest invitations",
		Query:          "AuditLogs | where OperationName == \"Invite external user\"",
		QueryFrequency: "PT1H",
		QueryPeriod:    "P1D",
		Mitre: []model.Mitre{
			{
				Tactics:    []string{"InitialAccess", "Persistence"},
				Techniques: []string{"T1078", "T1136"},
			},
		},
	}

	result := yamlToJson(a)

	t.Run("sets kind to Scheduled", func(t *testing.T) {
		if result.Kind != "Scheduled" {
			t.Errorf("Kind = %q, want Scheduled", result.Kind)
		}
	})

	t.Run("maps display name", func(t *testing.T) {
		if result.Properties.DisplayName != "External_guest_sign_in" {
			t.Errorf("DisplayName = %q, want External_guest_sign_in", result.Properties.DisplayName)
		}
	})

	t.Run("maps description", func(t *testing.T) {
		if result.Properties.Description != "Detects external guest invitations" {
			t.Errorf("Description = %q, want 'Detects external guest invitations'", result.Properties.Description)
		}
	})

	t.Run("maps severity", func(t *testing.T) {
		if result.Properties.Severity != "Medium" {
			t.Errorf("Severity = %q, want Medium", result.Properties.Severity)
		}
	})

	t.Run("maps query fields", func(t *testing.T) {
		if result.Properties.Query != "AuditLogs | where OperationName == \"Invite external user\"" {
			t.Errorf("Query mismatch")
		}
		if result.Properties.QueryFrequency != "PT1H" {
			t.Errorf("QueryFrequency = %q, want PT1H", result.Properties.QueryFrequency)
		}
		if result.Properties.QueryPeriod != "P1D" {
			t.Errorf("QueryPeriod = %q, want P1D", result.Properties.QueryPeriod)
		}
	})

	t.Run("sets defaults", func(t *testing.T) {
		if result.Properties.Enabled != true {
			t.Error("Enabled should be true")
		}
		if result.Properties.TriggerOperator != "GreaterThan" {
			t.Errorf("TriggerOperator = %q, want GreaterThan", result.Properties.TriggerOperator)
		}
		if result.Properties.TriggerThreshold != 0 {
			t.Errorf("TriggerThreshold = %d, want 0", result.Properties.TriggerThreshold)
		}
		if result.Properties.SuppressionEnabled != false {
			t.Error("SuppressionEnabled should be false")
		}
		if result.Properties.SuppressionDuration != "PT5H" {
			t.Errorf("SuppressionDuration = %q, want PT5H", result.Properties.SuppressionDuration)
		}
	})

	t.Run("extracts tactics", func(t *testing.T) {
		expected := []string{"InitialAccess", "Persistence"}
		if len(result.Properties.Tactics) != len(expected) {
			t.Errorf("Tactics length = %d, want %d", len(result.Properties.Tactics), len(expected))
		}
		for i, tactic := range result.Properties.Tactics {
			if tactic != expected[i] {
				t.Errorf("Tactics[%d] = %q, want %q", i, tactic, expected[i])
			}
		}
	})

	t.Run("extracts techniques", func(t *testing.T) {
		expected := []string{"T1078", "T1136"}
		if len(result.Properties.Techniques) != len(expected) {
			t.Errorf("Techniques length = %d, want %d", len(result.Properties.Techniques), len(expected))
		}
		for i, tech := range result.Properties.Techniques {
			if tech != expected[i] {
				t.Errorf("Techniques[%d] = %q, want %q", i, tech, expected[i])
			}
		}
	})
}