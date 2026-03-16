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

func SingleJSONtoYAML(outpath string, file string, test model.Testconv) {
	f, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(f, &test)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("read in: " + file)

	yamlout, err := yaml.Marshal(test)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(outpath+test.Name, yamlout, 0o644)
	if err != nil {
		log.Fatal(err)
	}
}

// rework to arm exported rules
func MultiJSONtoYAML(outpath string, file string, arm model.ARMTemplate) {
	f, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(f, &arm)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("read in: " + file)

	for i := range arm.Resources {

		yamlout, err := yaml.Marshal(armToAnalytic(arm.Resources[i].Properties))
		if err != nil {
			log.Fatal(err)
		}

		err = os.WriteFile(outpath+arm.Resources[i].Properties.DisplayName+".yaml", yamlout, 0o644)
		if err != nil {
			log.Fatalf("Error writing the file")
		}

	}
}

func SingleYAMLtoJSON(outpath string, file string, y model.Analytic) {
	f, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(f, &y)
	if err != nil {
		log.Fatal("Error Unmarshal the source ")
	}
	fmt.Println("read in: " + file)

	jsonout, err := json.Marshal(yamlToArm(y))
	if err != nil {
		log.Fatal("error marshal the dst")
	}

	err = os.WriteFile(outpath+y.Name+".json", jsonout, 0o644)
	if err != nil {
		log.Fatal("error writing the file")
	}
}

// build yaml layout from json
func armToAnalytic(arm model.ARMProperties) model.Analytic {
	return model.Analytic{
		Name:           arm.DisplayName,
		Severity:       arm.Severity,
		Description:    arm.Description,
		Query:          arm.Query,
		QueryFrequency: arm.QueryFrequency,
		QueryPeriod:    arm.QueryPeriod,
		Mitre: []model.Mitre{
			{
				Tactics:    arm.Tactics,
				Techniques: arm.Techniques,
			},
		},
		// add the entity mapping with separat function
	}
}

// build yaml layout from json
// lot of  hard coded stuff needs cleanup
// TODO how to get all mandatory arguments from the yaml ?
func yamlToArm(yaml model.Analytic) model.ARMTemplate {
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
				ID:         createARMId(yaml),
				Name:       createARMName(yaml),
				Type:       ARMRuleType,
				Kind:       "Scheduled",          // hard coded  for testing
				APIVersion: "2023-12-01-preview", // hardcoded for  testing
				Properties: model.ARMProperties{
					DisplayName:         yaml.Name,
					Description:         yaml.Description,
					Severity:            yaml.Severity,
					Enabled:             true,
					QueryFrequency:      yaml.QueryFrequency,
					QueryPeriod:         yaml.QueryPeriod,
					Query:               yaml.Query,
					Tactics:             extractTactics(yaml.Mitre),
					Techniques:          extractTechniques(yaml.Mitre),
					TriggerOperator:     "GreaterThan", // hardcoded test
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
				},
			},
		},
	}

	// add the entity mapping with separat function
}

func extractTactics(mitre []model.Mitre) []string {
	tactics := []string{}
	for _, m := range mitre {
		tactics = append(tactics, m.Tactics...)
	}
	return tactics
}

func extractTechniques(mitre []model.Mitre) []string {
	tactics := []string{}
	for _, m := range mitre {
		tactics = append(tactics, m.Techniques...)
	}
	return tactics
}

func createARMId(model model.Analytic) string {
	id := fmt.Sprintf("[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/%s')]", model.ID)
	return id
}

func createARMName(model model.Analytic) string {
	name := fmt.Sprintf("[concat(parameters('workspace'),'/Microsoft.SecurityInsights/%s')]", model.Name)
	return name
}
