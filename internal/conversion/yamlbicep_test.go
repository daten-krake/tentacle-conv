package conversion

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tentacle-conv/internal/model"
)

var update = os.Getenv("UPDATE_GOLDEN") == "1"

func TestGenerateBicepDSL(t *testing.T) {
	a := model.Analytic{
		Name:           "Files_with_double_extensions",
		Severity:       "Medium",
		Description:    "Detects double extension files",
		Query:          "DeviceProcessEvents\n| where FileName endswith \".pdf.exe\"",
		QueryFrequency: "PT20M",
		QueryPeriod:    "PT20M",
		Mitre: []model.Mitre{
			{
				Tactics:    []string{"DefenseEvasion", "InitialAccess"},
				Techniques: []string{"T1036"},
			},
		},
		EntityMapping: []model.Entities{
			{
				EntityType: "Host",
				FieldMapping: []model.FieldMapping{
					{Identifier: "FullName", ColumnName: "HostCustomEntity"},
				},
			},
		},
	}

	got, err := generateBicepDSL(a)
	if err != nil {
		t.Fatal(err)
	}

	goldenPath := filepath.Join("..", "..", "testdata", "out", "TestGenerateBicepDSL.bicep")
	if update {
		err := os.WriteFile(goldenPath, []byte(got), 0o644)
		if err != nil {
			t.Fatal(err)
		}
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}

	if got != string(want) {
		t.Errorf("output mismatch (-want +got):\n%s", diffBicep(string(want), got))
	}
}

func TestGenerateBicepDSL_SingleLineQuery(t *testing.T) {
	a := model.Analytic{
		Name:           "Single_Line_Query",
		Severity:       "Low",
		Description:    "Simple rule",
		Query:          "SigninLogs | where ResultType == 0",
		QueryFrequency: "PT1H",
		QueryPeriod:   "P1D",
	}

	got, err := generateBicepDSL(a)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(got, "'''") {
		t.Error("single-line query should not use heredoc syntax")
	}
	if !strings.Contains(got, "query: 'SigninLogs | where ResultType == 0'") {
		t.Error("single-line query should use single-quoted string")
	}
}

func TestGenerateBicepDSL_EmptyArrays(t *testing.T) {
	a := model.Analytic{
		Name:           "No_Mitre",
		Severity:       "Medium",
		Description:    "No MITRE data",
		Query:          "print 1",
		QueryFrequency: "PT5M",
		QueryPeriod:    "PT30M",
	}

	got, err := generateBicepDSL(a)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(got, "tactics: []") {
		t.Error("empty tactics should render as 'tactics: []'")
	}
	if !strings.Contains(got, "techniques: []") {
		t.Error("empty techniques should render as 'techniques: []'")
	}
}

func TestGenerateBicepDSL_SpecialChars(t *testing.T) {
	a := model.Analytic{
		Name:           "Test_Special_Chars",
		Severity:       "High",
		Description:    "Rule with 'single quotes' in name",
		Query:          "SomeTable | where Field == 'value'",
		QueryFrequency: "PT1H",
		QueryPeriod:    "P1D",
		Mitre: []model.Mitre{
			{
				Tactics: []string{"Execution"},
				Techniques: []string{"T1059.001"},
			},
		},
	}

	got, err := generateBicepDSL(a)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(got, "Rule with ''single quotes'' in name") {
		t.Error("single quotes should be escaped for description")
	}
	if !strings.Contains(got, "SomeTable | where Field == ''value''") {
		t.Error("single quotes in query should be escaped")
	}
	if !strings.Contains(got, "T1059.001") {
		t.Error("techniques with dots should be preserved")
	}
}

func TestGenerateBicepDSL_WorkspaceParam(t *testing.T) {
	a := model.Analytic{
		Name:           "Test_Rule",
		Severity:       "Medium",
		Description:    "Test",
		Query:          "print 1",
		QueryFrequency: "PT1H",
		QueryPeriod:    "P1D",
	}

	got, err := generateBicepDSL(a)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(got, "param workspace string") {
		t.Error("should include workspace parameter")
	}
	if !strings.Contains(got, "${workspace}/Microsoft.SecurityInsights/Test_Rule") {
		t.Error("resource name should be parameterized with workspace")
	}
	if !strings.Contains(got, "resource alertRule") {
		t.Error("should include resource declaration")
	}
}

func diffBicep(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	var b strings.Builder
	max := len(wantLines)
	if len(gotLines) > max {
		max = len(gotLines)
	}
	for i := 0; i < max; i++ {
		var w, g string
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w != g {
			fmt.Fprintf(&b, "-L%d: %s\n+L%d: %s\n", i+1, w, i+1, g)
		}
	}
	return b.String()
}
