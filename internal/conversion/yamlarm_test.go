package conversion

import (
	"testing"

	"github.com/tentacle-conv/internal/model"
)

func sampleAnalytic() model.Analytic {
	return model.Analytic{
		Name:           "Test_Rule",
		Severity:       "High",
		Description:    "A test detection rule",
		Query:          "SecurityEvent | where EventID == 4624",
		QueryFrequency: "PT1H",
		QueryPeriod:    "PT2H",
		Mitre: []model.Mitre{
			{
				Tactics:    []string{"Execution", "Persistence"},
				Techniques: []string{"T1059", "T1078"},
			},
		},
		EntityMapping: []model.Entities{
			{
				EntityType: "Account",
				FieldMapping: []model.FieldMapping{
					{Identifier: "FullName", ColumnName: "AccountName"},
					{Identifier: "Name", ColumnName: "AccountShortName"},
				},
			},
		},
	}
}

func TestYamlToArm(t *testing.T) {
	a := sampleAnalytic()
	result := yamlToArm(a)

	t.Run("sets ARM template schema and version", func(t *testing.T) {
		if result.Schema != ARMSchema {
			t.Errorf("Schema = %q, want %q", result.Schema, ARMSchema)
		}
		if result.ContentVersion != ARMContentVersion {
			t.Errorf("ContentVersion = %q, want %q", result.ContentVersion, ARMContentVersion)
		}
	})

	t.Run("sets workspace parameter", func(t *testing.T) {
		params, ok := result.Parameters.(map[string]interface{})
		if !ok {
			t.Fatal("Parameters is not a map")
		}
		ws, ok := params["workspace"]
		if !ok {
			t.Fatal("workspace parameter not found")
		}
		wsMap, ok := ws.(map[string]interface{})
		if !ok {
			t.Fatal("workspace parameter is not a map")
		}
		if wsMap["type"] != "String" {
			t.Errorf("workspace type = %v, want String", wsMap["type"])
		}
	})

	t.Run("maps resource fields correctly", func(t *testing.T) {
		if len(result.Resources) != 1 {
			t.Fatalf("Resources length = %d, want 1", len(result.Resources))
		}
		res := result.Resources[0]
		if res.Type != ARMRuleType {
			t.Errorf("Type = %q, want %q", res.Type, ARMRuleType)
		}
		if res.Kind != "Scheduled" {
			t.Errorf("Kind = %q, want Scheduled", res.Kind)
		}
		if res.APIVersion != "2023-12-01-preview" {
			t.Errorf("APIVersion = %q, want 2023-12-01-preview", res.APIVersion)
		}

		p := res.Properties
		if p.DisplayName != "Test_Rule" {
			t.Errorf("DisplayName = %q, want Test_Rule", p.DisplayName)
		}
		if p.Description != "A test detection rule" {
			t.Errorf("Description = %q, want 'A test detection rule'", p.Description)
		}
		if p.Severity != "High" {
			t.Errorf("Severity = %q, want High", p.Severity)
		}
		if p.Query != "SecurityEvent | where EventID == 4624" {
			t.Errorf("Query mismatch")
		}
		if p.QueryFrequency != "PT1H" {
			t.Errorf("QueryFrequency = %q, want PT1H", p.QueryFrequency)
		}
		if p.QueryPeriod != "PT2H" {
			t.Errorf("QueryPeriod = %q, want PT2H", p.QueryPeriod)
		}
		if p.Enabled != true {
			t.Error("Enabled should be true")
		}
		if p.TriggerOperator != "GreaterThan" {
			t.Errorf("TriggerOperator = %q, want GreaterThan", p.TriggerOperator)
		}
		if p.TriggerThreshold != 0 {
			t.Errorf("TriggerThreshold = %d, want 0", p.TriggerThreshold)
		}
		if p.SuppressionDuration != "PT5H" {
			t.Errorf("SuppressionDuration = %q, want PT5H", p.SuppressionDuration)
		}
		if p.SuppressionEnabled != false {
			t.Error("SuppressionEnabled should be false")
		}
	})

	t.Run("extracts MITRE tactics and techniques", func(t *testing.T) {
		res := result.Resources[0]
		p := res.Properties
		expectedTactics := []string{"Execution", "Persistence"}
		expectedTechniques := []string{"T1059", "T1078"}

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

	t.Run("maps entity mappings from YAML to ARM", func(t *testing.T) {
		p := result.Resources[0].Properties
		if len(p.EntityMappings) != 1 {
			t.Fatalf("EntityMappings length = %d, want 1", len(p.EntityMappings))
		}
		em := p.EntityMappings[0]
		if em.EntityType != "Account" {
			t.Errorf("EntityType = %q, want Account", em.EntityType)
		}
		if len(em.FieldMappings) != 2 {
			t.Fatalf("FieldMappings length = %d, want 2", len(em.FieldMappings))
		}
		if em.FieldMappings[0].Identifier != "FullName" || em.FieldMappings[0].ColumnName != "AccountName" {
			t.Errorf("FieldMappings[0] = %+v, want Identifier=FullName ColumnName=AccountName", em.FieldMappings[0])
		}
		if em.FieldMappings[1].Identifier != "Name" || em.FieldMappings[1].ColumnName != "AccountShortName" {
			t.Errorf("FieldMappings[1] = %+v, want Identifier=Name ColumnName=AccountShortName", em.FieldMappings[1])
		}
	})
}

func TestBuildARMEntityMappings(t *testing.T) {
	tests := []struct {
		name   string
		input  []model.Entities
		expect []model.ARMEntityMapping
	}{
		{
			name:   "nil input",
			input:  nil,
			expect: nil,
		},
		{
			name:   "empty input",
			input:  []model.Entities{},
			expect: []model.ARMEntityMapping{},
		},
		{
			name: "single entity with field mappings",
			input: []model.Entities{
				{
					EntityType: "Host",
					FieldMapping: []model.FieldMapping{
						{Identifier: "FullName", ColumnName: "Computer"},
					},
				},
			},
			expect: []model.ARMEntityMapping{
				{
					EntityType: "Host",
					FieldMappings: []model.ARMFieldMapping{
						{Identifier: "FullName", ColumnName: "Computer"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildARMEntityMappings(tt.input)
			if len(got) != len(tt.expect) {
				t.Errorf("got %d mappings, want %d", len(got), len(tt.expect))
				return
			}
			for i, m := range got {
				if m.EntityType != tt.expect[i].EntityType {
					t.Errorf("mapping[%d].EntityType = %q, want %q", i, m.EntityType, tt.expect[i].EntityType)
				}
				if len(m.FieldMappings) != len(tt.expect[i].FieldMappings) {
					t.Errorf("mapping[%d].FieldMappings length = %d, want %d", i, len(m.FieldMappings), len(tt.expect[i].FieldMappings))
				}
			}
		})
	}
}

func TestCreateARMId(t *testing.T) {
	a := model.Analytic{Name: "MyDetectionRule"}
	result := createARMId(a)
	expected := "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/MyDetectionRule')]"
	if result != expected {
		t.Errorf("createARMId = %q, want %q", result, expected)
	}
}

func TestCreateARMName(t *testing.T) {
	a := model.Analytic{Name: "MyDetectionRule"}
	result := createARMName(a)
	expected := "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/MyDetectionRule')]"
	if result != expected {
		t.Errorf("createARMName = %q, want %q", result, expected)
	}
}