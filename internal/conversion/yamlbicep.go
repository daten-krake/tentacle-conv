package conversion

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

// bicepData is the template input: the same rule properties the ARM and REST
// outputs use, plus the resource name.
type bicepData struct {
	ID         string
	Kind       string
	APIVersion string
	Props      model.ARMProperties
}

var bicepFuncs = template.FuncMap{
	"bicepEscape": bicepEscape,
	"bicepQuery":  bicepQuery,
}

// bicepEscape escapes text for the inside of a single-quoted Bicep string.
func bicepEscape(s string) string {
	return bicepStringEscaper.Replace(s)
}

// bicepStringEscaper escapes text for a single-quoted Bicep string literal.
var bicepStringEscaper = strings.NewReplacer(
	`\`, `\\`,
	`'`, `\'`,
	"${", `\${`,
	"\n", `\n`,
	"\r", `\r`,
	"\t", `\t`,
)

// bicepQuery renders a KQL query as a Bicep string literal whose value is
// exactly the query text. Multi-line queries use a ”' string, which Bicep
// takes verbatim (no escapes, no interpolation); the newline right after the
// opening ”' is ignored and the closing ”' follows the text directly so no
// newline is added. Queries a ”' string cannot represent fall back to an
// escaped single-quoted string.
func bicepQuery(query string) string {
	if strings.Contains(query, "\n") &&
		!strings.Contains(query, "'''") &&
		!strings.HasSuffix(query, "'") {
		return "'''\n" + query + "'''"
	}
	return "'" + bicepEscape(query) + "'"
}

var bicepTmpl = template.Must(template.New("bicep").Funcs(bicepFuncs).Parse(`param workspace string

resource alertRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@{{.APIVersion}}' = {
  name: '${workspace}/Microsoft.SecurityInsights/{{.ID | bicepEscape}}'
  kind: '{{.Kind | bicepEscape}}'
  properties: {
    displayName: '{{.Props.DisplayName | bicepEscape}}'
    description: '{{.Props.Description | bicepEscape}}'
    severity: '{{.Props.Severity | bicepEscape}}'
    enabled: {{.Props.Enabled}}
    query: {{.Props.Query | bicepQuery}}
    queryFrequency: '{{.Props.QueryFrequency | bicepEscape}}'
    queryPeriod: '{{.Props.QueryPeriod | bicepEscape}}'
    triggerOperator: '{{.Props.TriggerOperator | bicepEscape}}'
    triggerThreshold: {{.Props.TriggerThreshold}}
    suppressionDuration: '{{.Props.SuppressionDuration | bicepEscape}}'
    suppressionEnabled: {{.Props.SuppressionEnabled}}
    tactics: [{{range $i, $t := .Props.Tactics}}{{if $i}}, {{end}}'{{$t | bicepEscape}}'{{end}}]
    techniques: [{{range $i, $t := .Props.Techniques}}{{if $i}}, {{end}}'{{$t | bicepEscape}}'{{end}}]
    subTechniques: [{{range $i, $t := .Props.SubTechniques}}{{if $i}}, {{end}}'{{$t | bicepEscape}}'{{end}}]
    entityMappings: [{{- range .Props.EntityMappings }}
      {
        entityType: '{{.EntityType | bicepEscape}}'
        fieldMappings: [{{- range .FieldMappings }}
          {
            identifier: '{{.Identifier | bicepEscape}}'
            columnName: '{{.ColumnName | bicepEscape}}'
          }{{- end }}
        ]
      }{{- end }}
    ]
    incidentConfiguration: {
      createIncident: {{.Props.IncidentConfiguration.CreateIncident}}
      groupingConfiguration: {
        enabled: {{.Props.IncidentConfiguration.GroupingConfiguration.Enabled}}
        lookbackDuration: '{{.Props.IncidentConfiguration.GroupingConfiguration.LookbackDuration | bicepEscape}}'
        matchingMethod: '{{.Props.IncidentConfiguration.GroupingConfiguration.MatchingMethod | bicepEscape}}'
      }
    }
    eventGroupingSettings: {
      aggregationKind: '{{.Props.EventGroupingSettings.AggregationKind | bicepEscape}}'
    }
  }
}
`))

// SingleYAMLtoBicep reads a YAML analytic file, converts it to a Bicep alert
// rule resource, and writes the result to outpath.
func SingleYAMLtoBicep(outpath string, file string) error {
	y, err := loadAnalytic(file)
	if err != nil {
		return err
	}

	bicepOut, err := generateBicepDSL(y)
	if err != nil {
		return fmt.Errorf("generating Bicep DSL: %w", err)
	}

	return writeOutput(outpath, y.Name, "bicep", []byte(bicepOut))
}

func generateBicepDSL(a model.Analytic) (string, error) {
	data := bicepData{
		ID:         ruleID(a),
		Kind:       ruleKind,
		APIVersion: ruleAPIVersion,
		Props:      ruleProperties(a),
	}

	var buf bytes.Buffer
	err := bicepTmpl.Execute(&buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
