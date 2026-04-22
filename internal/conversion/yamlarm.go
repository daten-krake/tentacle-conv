package conversion

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/tentacle-conv/internal/model"
	"gopkg.in/yaml.v3"
)

const (
	ARMSchema         = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
	ARMContentVersion = "1.0.0.0"
	ARMRuleType       = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
)

func SingleYAMLtoARM(outpath string, file string, y model.Analytic) {
	f, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(f, &y)
	if err != nil {
		log.Fatal("Error Unmarshal the source ")
	}
	println("read in: " + file)

	jsonout, err := json.Marshal(yamlToArm(y))
	if err != nil {
		log.Fatal("error marshal the dst")
	}

	err = os.WriteFile(outpath+y.Name+".json", jsonout, 0o644)
	if err != nil {
		log.Fatal("error writing the file")
	}
}

func yamlToArm(a model.Analytic) model.ARMTemplate {
	return model.ARMTemplate{
		Schema:         ARMSchema,
		ContentVersion: ARMContentVersion,
		Parameters: map[string]interface{}{
			"workspace": map[string]interface{}{
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
					Description:        a.Description,
					Severity:           a.Severity,
					Enabled:            true,
					QueryFrequency:     a.QueryFrequency,
					QueryPeriod:        a.QueryPeriod,
					Query:              a.Query,
					Tactics:            extractTactics(a.Mitre),
					Techniques:         extractTechniques(a.Mitre),
					TriggerOperator:    "GreaterThan",
					TriggerThreshold:   0,
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

func createARMId(a model.Analytic) string {
	return fmt.Sprintf("[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/%s')]", a.Name)
}

func createARMName(a model.Analytic) string {
	return fmt.Sprintf("[concat(parameters('workspace'),'/Microsoft.SecurityInsights/%s')]", a.Name)
}