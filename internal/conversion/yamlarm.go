package conversion

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

const (
	ARMSchema         = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
	ARMContentVersion = "1.0.0.0"
	ARMRuleType       = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
)

// SingleYAMLtoARM reads a YAML analytic file, converts it to an ARM template
// JSON, and writes the result to outpath.
func SingleYAMLtoARM(outpath string, file string) error {
	y, err := loadAnalytic(file)
	if err != nil {
		return err
	}

	jsonout, err := json.Marshal(yamlToArm(y))
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}

	return writeOutput(outpath, y.Name, "json", jsonout)
}

// yamlToArm maps a prodyaml Analytic model to a full ARM template including
// default incident and grouping configuration.
func yamlToArm(a model.Analytic) model.ARMTemplate {
	id := ruleID(a)
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
				ID:         createARMId(id),
				Name:       createARMName(id),
				Type:       ARMRuleType,
				Kind:       ruleKind,
				APIVersion: ruleAPIVersion,
				Properties: ruleProperties(a),
			},
		},
	}
}

// buildARMEntityMappings converts a slice of prodyaml Entities to ARM entity
// mappings. The result is never nil, so it serializes as [] rather than null.
func buildARMEntityMappings(input []model.Entities) []model.ARMEntityMapping {
	result := []model.ARMEntityMapping{}

	for _, em := range input {
		entity := model.ARMEntityMapping{
			EntityType:    em.EntityType,
			FieldMappings: []model.ARMFieldMapping{},
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

// armEscape escapes a value for use inside a single-quoted literal of an ARM
// template expression.
func armEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// createARMId generates an ARM template resource ID for the rule ID.
func createARMId(id string) string {
	return fmt.Sprintf("[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/%s')]", armEscape(id))
}

// createARMName generates an ARM template resource name for the rule ID.
func createARMName(id string) string {
	return fmt.Sprintf("[concat(parameters('workspace'),'/Microsoft.SecurityInsights/%s')]", armEscape(id))
}
