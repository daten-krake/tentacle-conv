package conversion

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/tentacle-conv/internal/model"
	"gopkg.in/yaml.v3"
)

const (
	ARMSchema         = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
	ARMContentVersion = "1.0.0.0"
	ARMRuleType       = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
)

// SingleYAMLtoARM reads a YAML analytic file, converts it to an ARM template
// JSON, and writes the result to outpath.
func SingleYAMLtoARM(outpath string, file string, y model.Analytic) error {
	f, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", file, err)
	}
	err = yaml.Unmarshal(f, &y)
	if err != nil {
		return fmt.Errorf("unmarshaling YAML from %s: %w", file, err)
	}
	log.Println("read in: " + file)

	jsonout, err := json.Marshal(yamlToArm(y))
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}

	outFile := filepath.Join(outpath, y.Name+".json")
	err = os.WriteFile(outFile, jsonout, 0o644)
	if err != nil {
		return fmt.Errorf("writing file %s: %w", outFile, err)
	}
	return nil
}

// yamlToArm maps a prodyaml Analytic model to a full ARM template including
// default incident and grouping configuration.
func yamlToArm(a model.Analytic) model.ARMTemplate {
	return model.ARMTemplate{
		Schema:         ARMSchema,
		ContentVersion: ARMContentVersion,
		Parameters: map[string]any{
			"workspace": map[string]any{
				"type": "String",
			},
		},
		Resources: []model.ARMResource{
			{
				ID:         createARMId(a),
				Name:       createARMName(a),
				Type:       ARMRuleType,
				Kind:       "Scheduled",
				APIVersion: "2023-12-01-preview",
				Properties: model.ARMProperties{
					DisplayName:         a.Name,
					Description:         a.Description,
					Severity:            a.Severity,
					Enabled:             true,
					QueryFrequency:      a.QueryFrequency,
					QueryPeriod:         a.QueryPeriod,
					Query:               a.Query,
					Tactics:             extractTactics(a.Mitre),
					Techniques:          extractTechniques(a.Mitre),
					TriggerOperator:     "GreaterThan",
					TriggerThreshold:    0,
					SuppressionDuration: "PT5H",
					SuppressionEnabled:  false,
					IncidentConfiguration: model.IncidentConfiguration{
						CreateIncident: true,
						GroupingConfiguration: model.GroupingConfiguration{
							Enabled:          true,
							LookbackDuration: "P7D",
							MatchingMethod:   "AllEntities",
						},
					},
					EventGroupingSettings: model.EventGroupingSettings{
						AggregationKind: "AlertPerResult",
					},
					EntityMappings: buildARMEntityMappings(a.EntityMapping),
				},
			},
		},
	}
}

// buildARMEntityMappings converts a slice of prodyaml Entities to ARM entity
// mappings.
func buildARMEntityMappings(input []model.Entities) []model.ARMEntityMapping {
	var result []model.ARMEntityMapping

	for _, em := range input {
		entity := model.ARMEntityMapping{
			EntityType: em.EntityType,
		}

		for _, fm := range em.FieldMapping {
			entity.FieldMappings = append(entity.FieldMappings, model.ARMFieldMapping{
				Identifier: fm.Identifier,
				ColumnName: fm.ColumnName,
			})
		}

		result = append(result, entity)
	}

	return result
}

// createARMId generates an ARM template resource ID using the analytic name.
func createARMId(a model.Analytic) string {
	return fmt.Sprintf("[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/%s')]", a.Name)
}

// createARMName generates an ARM template resource name using the analytic name.
func createARMName(a model.Analytic) string {
	return fmt.Sprintf("[concat(parameters('workspace'),'/Microsoft.SecurityInsights/%s')]", a.Name)
}