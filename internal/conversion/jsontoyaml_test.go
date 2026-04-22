package conversion

import (
	"testing"

	"github.com/tentacle-conv/internal/model"
)

func TestArmToAnalytic(t *testing.T) {
	tests := []struct {
		name string
		arm  model.ARMProperties
		want model.Analytic
	}{
		{
			name: "basic ARM to Analytic conversion",
			arm: model.ARMProperties{
				DisplayName:    "Test_Rule",
				Description:    "Test description",
				Severity:       "High",
				Query:          "SecurityEvent | where EventID == 4624",
				QueryFrequency: "PT1H",
				QueryPeriod:    "PT2H",
				Tactics:        []string{"Execution", "Persistence"},
				Techniques:     []string{"T1059", "T1078"},
				EntityMappings: []model.ARMEntityMapping{
					{
						EntityType: "Account",
						FieldMappings: []model.ARMFieldMapping{
							{Identifier: "FullName", ColumnName: "AccountName"},
						},
					},
				},
			},
			want: model.Analytic{
				Name:           "Test_Rule",
				Severity:       "High",
				Description:    "Test description",
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
						},
					},
				},
			},
		},
		{
			name: "ARM with no entity mappings",
			arm: model.ARMProperties{
				DisplayName:    "NoEntities",
				Description:    "No entities",
				Severity:       "Medium",
				Query:          "print 1",
				QueryFrequency: "PT5M",
				QueryPeriod:    "PT30M",
				Tactics:        []string{"DefenseEvasion"},
				Techniques:     []string{"T1036"},
				EntityMappings: nil,
			},
			want: model.Analytic{
				Name:           "NoEntities",
				Severity:       "Medium",
				Description:    "No entities",
				Query:          "print 1",
				QueryFrequency: "PT5M",
				QueryPeriod:    "PT30M",
				Mitre: []model.Mitre{
					{
						Tactics:    []string{"DefenseEvasion"},
						Techniques: []string{"T1036"},
					},
				},
				EntityMapping: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := armToAnalytic(tt.arm)
			if got.Name != tt.want.Name {
				t.Errorf("Name = %q, want %q", got.Name, tt.want.Name)
			}
			if got.Severity != tt.want.Severity {
				t.Errorf("Severity = %q, want %q", got.Severity, tt.want.Severity)
			}
			if got.Description != tt.want.Description {
				t.Errorf("Description = %q, want %q", got.Description, tt.want.Description)
			}
			if got.Query != tt.want.Query {
				t.Errorf("Query = %q, want %q", got.Query, tt.want.Query)
			}
			if got.QueryFrequency != tt.want.QueryFrequency {
				t.Errorf("QueryFrequency = %q, want %q", got.QueryFrequency, tt.want.QueryFrequency)
			}
			if got.QueryPeriod != tt.want.QueryPeriod {
				t.Errorf("QueryPeriod = %q, want %q", got.QueryPeriod, tt.want.QueryPeriod)
			}
			if len(got.Mitre) != len(tt.want.Mitre) {
				t.Errorf("Mitre length = %d, want %d", len(got.Mitre), len(tt.want.Mitre))
			} else {
				for i, m := range got.Mitre {
					if len(m.Tactics) != len(tt.want.Mitre[i].Tactics) {
						t.Errorf("Mitre[%d].Tactics length = %d, want %d", i, len(m.Tactics), len(tt.want.Mitre[i].Tactics))
					}
					if len(m.Techniques) != len(tt.want.Mitre[i].Techniques) {
						t.Errorf("Mitre[%d].Techniques length = %d, want %d", i, len(m.Techniques), len(tt.want.Mitre[i].Techniques))
					}
				}
			}
			if len(got.EntityMapping) != len(tt.want.EntityMapping) {
				t.Errorf("EntityMapping length = %d, want %d", len(got.EntityMapping), len(tt.want.EntityMapping))
			}
		})
	}
}

func TestBuildYamlEntityMappings(t *testing.T) {
	tests := []struct {
		name   string
		input  []model.ARMEntityMapping
		expect []model.Entities
	}{
		{
			name:   "nil input",
			input:  nil,
			expect: nil,
		},
		{
			name:   "empty input",
			input:  []model.ARMEntityMapping{},
			expect: []model.Entities{},
		},
		{
			name: "single entity with single field mapping",
			input: []model.ARMEntityMapping{
				{
					EntityType: "Account",
					FieldMappings: []model.ARMFieldMapping{
						{Identifier: "FullName", ColumnName: "AccountName"},
					},
				},
			},
			expect: []model.Entities{
				{
					EntityType: "Account",
					FieldMapping: []model.FieldMapping{
						{Identifier: "FullName", ColumnName: "AccountName"},
					},
				},
			},
		},
		{
			name: "multiple entities with multiple field mappings",
			input: []model.ARMEntityMapping{
				{
					EntityType: "Host",
					FieldMappings: []model.ARMFieldMapping{
						{Identifier: "FullName", ColumnName: "Computer"},
						{Identifier: "HostName", ColumnName: "HostName"},
					},
				},
				{
					EntityType: "IP",
					FieldMappings: []model.ARMFieldMapping{
						{Identifier: "Address", ColumnName: "IPAddress"},
					},
				},
			},
			expect: []model.Entities{
				{
					EntityType: "Host",
					FieldMapping: []model.FieldMapping{
						{Identifier: "FullName", ColumnName: "Computer"},
						{Identifier: "HostName", ColumnName: "HostName"},
					},
				},
				{
					EntityType: "IP",
					FieldMapping: []model.FieldMapping{
						{Identifier: "Address", ColumnName: "IPAddress"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildYamlEntityMappings(tt.input)
			if len(got) != len(tt.expect) {
				t.Errorf("got %d entities, want %d", len(got), len(tt.expect))
				return
			}
			for i, e := range got {
				if e.EntityType != tt.expect[i].EntityType {
					t.Errorf("entity[%d].EntityType = %q, want %q", i, e.EntityType, tt.expect[i].EntityType)
				}
				if len(e.FieldMapping) != len(tt.expect[i].FieldMapping) {
					t.Errorf("entity[%d].FieldMapping length = %d, want %d", i, len(e.FieldMapping), len(tt.expect[i].FieldMapping))
				} else {
					for j, fm := range e.FieldMapping {
						if fm.Identifier != tt.expect[i].FieldMapping[j].Identifier {
							t.Errorf("entity[%d].FieldMapping[%d].Identifier = %q, want %q", i, j, fm.Identifier, tt.expect[i].FieldMapping[j].Identifier)
						}
						if fm.ColumnName != tt.expect[i].FieldMapping[j].ColumnName {
							t.Errorf("entity[%d].FieldMapping[%d].ColumnName = %q, want %q", i, j, fm.ColumnName, tt.expect[i].FieldMapping[j].ColumnName)
						}
					}
				}
			}
		})
	}
}