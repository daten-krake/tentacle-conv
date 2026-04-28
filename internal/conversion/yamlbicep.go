package conversion

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/tentacle-conv/internal/model"
	"gopkg.in/yaml.v3"
)

type bicepData struct {
	Name           string
	Description    string
	Severity       string
	Query          string
	QueryFrequency string
	QueryPeriod    string
	Tactics        []string
	Techniques     []string
	EntityMappings []model.Entities
}

var bicepFuncs = template.FuncMap{
	"bicepEscape": func(s string) string {
		return strings.ReplaceAll(s, "'", "''")
	},
	"bicepQuery": func(query string) string {
		escaped := strings.ReplaceAll(query, "'", "''")
		if strings.Contains(escaped, "\n") {
			return "'''\n" + escaped + "\n'''"
		}
		return "'" + escaped + "'"
	},
}

var bicepTmpl = template.Must(template.New("bicep").Funcs(bicepFuncs).Parse(`param workspace string

resource alertRule 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspace}/Microsoft.SecurityInsights/{{.Name}}'
  kind: 'Scheduled'
  properties: {
    displayName: '{{.Name | bicepEscape}}'
    description: '{{.Description | bicepEscape}}'
    severity: '{{.Severity}}'
    enabled: true
    query: {{.Query | bicepQuery}}
    queryFrequency: '{{.QueryFrequency}}'
    queryPeriod: '{{.QueryPeriod}}'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [{{range $i, $t := .Tactics}}{{if $i}}, {{end}}'{{$t | bicepEscape}}'{{end}}]
    techniques: [{{range $i, $t := .Techniques}}{{if $i}}, {{end}}'{{$t | bicepEscape}}'{{end}}]
    entityMappings: [{{- range .EntityMappings }}
      {
        entityType: '{{.EntityType}}'
        fieldMappings: [{{- range .FieldMapping }}
          {
            identifier: '{{.Identifier}}'
            columnName: '{{.ColumnName | bicepEscape}}'
          }{{- end }}
        ]
      }{{- end }}
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        lookbackDuration: 'P7D'
        matchingMethod: 'AllEntities'
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
  }
}
`))

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

	bicepOut, err := generateBicepDSL(y)
	if err != nil {
		return fmt.Errorf("generating Bicep DSL: %w", err)
	}

	outFile := filepath.Join(outpath, y.Name+".bicep")
	err = os.WriteFile(outFile, []byte(bicepOut), 0o644)
	if err != nil {
		return fmt.Errorf("writing file %s: %w", outFile, err)
	}
	return nil
}

func generateBicepDSL(a model.Analytic) (string, error) {
	data := bicepData{
		Name:           a.Name,
		Description:    a.Description,
		Severity:       a.Severity,
		Query:          a.Query,
		QueryFrequency: a.QueryFrequency,
		QueryPeriod:    a.QueryPeriod,
		Tactics:        extractTactics(a.Mitre),
		Techniques:     extractTechniques(a.Mitre),
		EntityMappings: a.EntityMapping,
	}

	var buf bytes.Buffer
	err := bicepTmpl.Execute(&buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
