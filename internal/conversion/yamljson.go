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

// SingleYAMLtoJSON reads a YAML analytic file, converts it to a Sentinel API
// JSON alert rule, and writes the result to outpath.
func SingleYAMLtoJSON(outpath string, file string, y model.Analytic) error {
	f, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", file, err)
	}
	err = yaml.Unmarshal(f, &y)
	if err != nil {
		return fmt.Errorf("unmarshaling YAML from %s: %w", file, err)
	}
	log.Println("read in: " + file)

	jsonout, err := json.Marshal(yamlToJson(y))
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

// yamlToJson maps a prodyaml Analytic model to a SentinelAlertRule model with
// sensible defaults for required fields.
func yamlToJson(a model.Analytic) model.SentinelAlertRule {
	return model.SentinelAlertRule{
		Kind: "Scheduled",
		Properties: model.SentinelRuleProperties{
			DisplayName:         a.Name,
			Description:         a.Description,
			Severity:            a.Severity,
			Enabled:             true,
			Query:               a.Query,
			QueryFrequency:      a.QueryFrequency,
			QueryPeriod:         a.QueryPeriod,
			TriggerOperator:     "GreaterThan",
			TriggerThreshold:    0,
			SuppressionEnabled:  false,
			SuppressionDuration: "PT5H",
			Tactics:             extractTactics(a.Mitre),
			Techniques:          extractTechniques(a.Mitre),
		},
	}
}