package conversion

import (
	"encoding/json"
	"log"
	"os"

	"github.com/tentacle-conv/internal/model"
	"gopkg.in/yaml.v3"
)

func SingleYAMLtoJSON(outpath string, file string, y model.Analytic) {
	f, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(f, &y)
	if err != nil {
		log.Fatal("Error Unmarshal the source ")
	}
	println("read in: " + file)

	jsonout, err := json.Marshal(yamlToJson(y))
	if err != nil {
		log.Fatal("error marshal the dst")
	}

	err = os.WriteFile(outpath+y.Name+".json", jsonout, 0o644)
	if err != nil {
		log.Fatal("error writing the file")
	}
}

func yamlToJson(a model.Analytic) model.SentinelAlertRule {
	return model.SentinelAlertRule{
		Kind: "Scheduled",
		Properties: model.SentinelRuleProperties{
			DisplayName:         a.Name,
			Description:         a.Description,
			Severity:           a.Severity,
			Enabled:            true,
			Query:              a.Query,
			QueryFrequency:     a.QueryFrequency,
			QueryPeriod:        a.QueryPeriod,
			TriggerOperator:    "GreaterThan",
			TriggerThreshold:   0,
			SuppressionEnabled: false,
			SuppressionDuration: "PT5H",
			Tactics:            extractTactics(a.Mitre),
			Techniques:         extractTechniques(a.Mitre),
		},
	}
}