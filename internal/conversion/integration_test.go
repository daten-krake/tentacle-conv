package conversion

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daten-krake/tentacle-conv/internal/model"
	"gopkg.in/yaml.v3"
)

const validRuleYAML = `id: ABC-01
name: %s
severity: High
description: it's a "test"
query: |
  SecurityEvent
  | where EventID == 4624
query_frequency: PT1H
query_period: PT2H
mitre:
  - tactics: [Execution]
    techniques: [T1059.001, T1078]
entity_mapping:
  - entity_type: Account
    field_mapping:
      - identifier: FullName
        column_name: AccountName
`

func writeFileT(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func ruleFile(t *testing.T, name string) string {
	t.Helper()
	return writeFileT(t, t.TempDir(), "rule.yaml", strings.Replace(validRuleYAML, "%s", name, 1))
}

func readFileT(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSingleYAMLtoARM_WritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "does", "not", "exist")
	if err := SingleYAMLtoARM(out, ruleFile(t, "My_Rule")); err != nil {
		t.Fatal(err)
	}

	var tmpl model.ARMTemplate
	if err := json.Unmarshal(readFileT(t, filepath.Join(out, "My_Rule.json")), &tmpl); err != nil {
		t.Fatal(err)
	}
	res := tmpl.Resources[0]
	if want := "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/ABC-01')]"; res.Name != want {
		t.Errorf("Name = %q, want %q", res.Name, want)
	}
	p := res.Properties
	if strings.Join(p.Techniques, ",") != "T1059,T1078" || strings.Join(p.SubTechniques, ",") != "T1059.001" {
		t.Errorf("techniques = %v, subTechniques = %v", p.Techniques, p.SubTechniques)
	}
}

func TestSingleYAMLtoJSON_WritesFile(t *testing.T) {
	out := t.TempDir()
	if err := SingleYAMLtoJSON(out, ruleFile(t, "My_Rule")); err != nil {
		t.Fatal(err)
	}
	var rule model.SentinelAlertRule
	if err := json.Unmarshal(readFileT(t, filepath.Join(out, "My_Rule.json")), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.Kind != "Scheduled" || rule.Properties.DisplayName != "My_Rule" {
		t.Errorf("unexpected rule: %+v", rule)
	}
}

func TestSingleYAMLtoBicep_WritesFile(t *testing.T) {
	out := t.TempDir()
	if err := SingleYAMLtoBicep(out, ruleFile(t, "My_Rule")); err != nil {
		t.Fatal(err)
	}
	got := string(readFileT(t, filepath.Join(out, "My_Rule.bicep")))
	if !strings.Contains(got, `description: 'it\'s a "test"'`) {
		t.Errorf("description not escaped as expected:\n%s", got)
	}
}

func TestYAMLToX_UnsafeNamesStayInsideOutpath(t *testing.T) {
	convs := map[string]func(out, file string) error{
		"arm":   SingleYAMLtoARM,
		"json":  SingleYAMLtoJSON,
		"bicep": SingleYAMLtoBicep,
	}
	for mode, conv := range convs {
		t.Run(mode, func(t *testing.T) {
			parent := t.TempDir()
			out := filepath.Join(parent, "out")
			if err := conv(out, ruleFile(t, `"../../escape/Login/Logout"`)); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(out)
			if err != nil || len(entries) != 1 {
				t.Fatalf("expected exactly one file in outpath, got %v (err %v)", entries, err)
			}
			if strings.ContainsAny(entries[0].Name(), `/\`) || strings.HasPrefix(entries[0].Name(), ".") {
				t.Errorf("unsafe file name %q", entries[0].Name())
			}
			if _, err := os.Stat(filepath.Join(parent, "escape")); err == nil {
				t.Error("file written outside outpath")
			}
		})
	}
}

func TestYAMLToX_Errors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"missing":       filepath.Join(dir, "nope.yaml"),
		"invalid yaml":  writeFileT(t, dir, "bad.yaml", "name: [unclosed"),
		"empty":         writeFileT(t, dir, "empty.yaml", ""),
		"unknown field": writeFileT(t, dir, "typo.yaml", strings.Replace(validRuleYAML, "query_frequency", "query_freqency", 1)),
		"empty name":    writeFileT(t, dir, "noname.yaml", strings.Replace(validRuleYAML, "name: %s", `name: ""`, 1)),
		"bad severity":  writeFileT(t, dir, "sev.yaml", strings.Replace(strings.Replace(validRuleYAML, "%s", "R", 1), "severity: High", "severity: Critical", 1)),
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			for _, conv := range []func(string, string) error{SingleYAMLtoARM, SingleYAMLtoJSON, SingleYAMLtoBicep} {
				if err := conv(out, file); err == nil {
					t.Fatal("expected an error")
				}
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("failed conversion should not create the output directory")
			}
		})
	}
}

func TestSingleYAMLtoARM_UnwritableOutput(t *testing.T) {
	blocker := writeFileT(t, t.TempDir(), "file", "x")
	// outpath is a regular file, so it can be neither created nor written into.
	if err := SingleYAMLtoARM(filepath.Join(blocker, "sub"), ruleFile(t, "R")); err == nil {
		t.Fatal("expected an error")
	}
}

const armTemplate = `{
  "resources": [
    {"name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/RULE-1')]",
     "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules", "kind": "Scheduled",
     "properties": {"displayName": "Rule_One", "severity": "High", "query": "print 1",
       "queryFrequency": "PT1H", "queryPeriod": "PT1H", "tactics": ["Execution"],
       "techniques": ["T1059"], "subTechniques": ["T1059.001"]}},
    {"name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/NRT-1')]",
     "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules", "kind": "NRT",
     "properties": {"displayName": "Near_Real_Time", "severity": "Low", "query": "print 2"}},
    {"name": "meta", "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
     "properties": {"displayName": "Metadata"}}
  ]
}`

func TestMultiJSONtoYAML_FiltersAndKeepsID(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := MultiJSONtoYAML(out, writeFileT(t, dir, "arm.json", armTemplate)); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(out)
	if len(entries) != 1 || entries[0].Name() != "Rule_One.yaml" {
		t.Fatalf("expected only Rule_One.yaml, got %v", entries)
	}

	var a model.Analytic
	if err := yaml.Unmarshal(readFileT(t, filepath.Join(out, "Rule_One.yaml")), &a); err != nil {
		t.Fatal(err)
	}
	if a.ID != "RULE-1" {
		t.Errorf("ID = %q, want RULE-1", a.ID)
	}
	if got := strings.Join(a.Mitre[0].Techniques, ","); got != "T1059.001" {
		t.Errorf("techniques = %q, want T1059.001", got)
	}
}

func TestMultiJSONtoYAML_DuplicateAndUnsafeNames(t *testing.T) {
	res := func(name string) string {
		return `{"name": "x", "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules", "kind": "Scheduled", "properties": {"displayName": ` + name + `}}`
	}
	cases := map[string]string{
		"duplicate":           `{"resources": [` + res(`"Same"`) + `,` + res(`"Same"`) + `]}`,
		"duplicate after fix": `{"resources": [` + res(`"A/B"`) + `,` + res(`"A_B"`) + `]}`,
		"empty name":          `{"resources": [` + res(`""`) + `]}`,
		"dots only":           `{"resources": [` + res(`".."`) + `]}`,
		"blank":               `{"resources": [` + res(`"  "`) + `]}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "out")
			if err := MultiJSONtoYAML(out, writeFileT(t, dir, "arm.json", doc)); err == nil {
				t.Fatal("expected an error")
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("nothing should be written when a name is rejected")
			}
		})
	}
}

func TestSingleJSONtoYAML(t *testing.T) {
	dir := t.TempDir()
	one := `{"resources": [` + strings.SplitN(strings.SplitN(armTemplate, `"resources": [`, 2)[1], `,
    {"name": "[concat`, 2)[0] + `]}`

	t.Run("template with one rule", func(t *testing.T) {
		out := t.TempDir()
		if err := SingleJSONtoYAML(out, writeFileT(t, dir, "one.json", one)); err != nil {
			t.Fatal(err)
		}
		var a model.Analytic
		if err := yaml.Unmarshal(readFileT(t, filepath.Join(out, "Rule_One.yaml")), &a); err != nil {
			t.Fatal(err)
		}
		if a.Name != "Rule_One" || a.Query != "print 1" || a.ID != "RULE-1" {
			t.Errorf("unexpected analytic %+v", a)
		}
	})

	t.Run("bare resource", func(t *testing.T) {
		out := t.TempDir()
		bare := `{"name": "R-9", "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules", "kind": "Scheduled", "properties": {"displayName": "Bare"}}`
		if err := SingleJSONtoYAML(out, writeFileT(t, dir, "bare.json", bare)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(out, "Bare.yaml")); err != nil {
			t.Error(err)
		}
	})

	t.Run("several rules need -array", func(t *testing.T) {
		two := strings.Replace(armTemplate, `"kind": "NRT"`, `"kind": "Scheduled"`, 1)
		err := SingleJSONtoYAML(t.TempDir(), writeFileT(t, dir, "two.json", two))
		if err == nil || !strings.Contains(err.Error(), "-array") {
			t.Errorf("expected an error mentioning -array, got %v", err)
		}
	})

	t.Run("no rule", func(t *testing.T) {
		if err := SingleJSONtoYAML(t.TempDir(), writeFileT(t, dir, "none.json", `{"resources": []}`)); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("invalid JSON and missing file", func(t *testing.T) {
		if err := SingleJSONtoYAML(t.TempDir(), writeFileT(t, dir, "bad.json", "{")); err == nil {
			t.Error("expected an error for invalid JSON")
		}
		if err := SingleJSONtoYAML(t.TempDir(), filepath.Join(dir, "nope.json")); err == nil {
			t.Error("expected an error for a missing file")
		}
	})
}
