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

// SingleYAMLtoBicep reads a YAML analytic file, converts it to a Bicep JSON
// resource, and writes the result to outpath.
func SingleYAMLtoBicep(outpath string, file string, y model.Analytic) error {
	f, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", file, err)
	}
	err = yaml.Unmarshal(f, &y)
	if err != nil {
		return fmt.Errorf("unmarshaling YAML from %s: %w", file, err)
	}
	log.Println("read in: " + file)

	jsonout, err := json.Marshal(yamlToBicep(y))
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}

	outFile := filepath.Join(outpath, y.Name+".bicep")
	err = os.WriteFile(outFile, jsonout, 0o644)
	if err != nil {
		return fmt.Errorf("writing file %s: %w", outFile, err)
	}
	return nil
}

// yamlToBicep maps a prodyaml Analytic model to a BicepAlertRuleResource model
// with sensible defaults for required fields.
func yamlToBicep(a model.Analytic) model.BicepAlertRuleResource {
	return model.BicepAlertRuleResource{
		Name: a.Name,
		Kind: "Scheduled",
		Properties: model.AlertRuleProperties{
			DisplayName:           a.Name,
			Description:           a.Description,
			Severity:              a.Severity,
			Enabled:               true,
			Query:                 a.Query,
			QueryFrequency:        a.QueryFrequency,
			QueryPeriod:           a.QueryPeriod,
			TriggerOperator:       "GreaterThan",
			TriggerThreshold:      0,
			SuppressionEnabled:    false,
			SuppressionDuration:   "PT5H",
			Tactics:               extractTactics(a.Mitre),
			Techniques:            extractTechniques(a.Mitre),
			EventGroupingSettings: model.EventGroupingSettings{AggregationKind: "AlertPerResult"},
		},
	}
}