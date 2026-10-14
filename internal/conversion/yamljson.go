package conversion

import (
	"encoding/json"
	"fmt"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

// SingleYAMLtoJSON reads a YAML analytic file, converts it to a Sentinel API
// JSON alert rule, and writes the result to outpath.
func SingleYAMLtoJSON(outpath string, file string) error {
	y, err := loadAnalytic(file)
	if err != nil {
		return err
	}

	jsonout, err := json.Marshal(yamlToJson(y))
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}

	return writeOutput(outpath, y.Name, "json", jsonout)
}

// yamlToJson maps a prodyaml Analytic model to a SentinelAlertRule model. It
// uses the same properties as the ARM output.
func yamlToJson(a model.Analytic) model.SentinelAlertRule {
	return model.SentinelAlertRule{
		Kind:       ruleKind,
		Properties: ruleProperties(a),
	}
}
