package conversion

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

// goldenAnalytic exercises every mapped field, including sub-techniques,
// several entity types and characters that need escaping.
func goldenAnalytic() model.Analytic {
	return model.Analytic{
		ID:             "EVA-MDFE-01",
		Name:           "Golden rule with 'quotes'",
		Severity:       "Medium",
		Description:    "Detects things.\nSecond line with ${braces} and C:\\path.",
		Query:          "DeviceProcessEvents\n| where FileName endswith \".pdf.exe\"\n| where InitiatingProcessFileName != 'explorer.exe'",
		QueryFrequency: "PT20M",
		QueryPeriod:    "PT1H",
		Mitre: []model.Mitre{
			{Tactics: []string{"DefenseEvasion", "InitialAccess"}, Techniques: []string{"T1036", "T1036.007"}},
			{Tactics: []string{"Execution"}, Techniques: []string{"T1059.001"}},
		},
		EntityMapping: []model.Entities{
			{EntityType: "Host", FieldMapping: []model.FieldMapping{{Identifier: "FullName", ColumnName: "DeviceName"}}},
			{EntityType: "Account", FieldMapping: []model.FieldMapping{
				{Identifier: "Name", ColumnName: "AccountName"},
				{Identifier: "NTDomain", ColumnName: "AccountDomain"},
			}},
		},
	}
}

// checkGolden compares got with testdata/out/<name>, or rewrites the file when
// UPDATE_GOLDEN=1.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "out", name)
	if update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with UPDATE_GOLDEN=1 to create it)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs (run with UPDATE_GOLDEN=1 to accept):\n%s", name, diffBicep(string(want), string(got)))
	}
}

func TestGoldenARM(t *testing.T) {
	b, err := json.MarshalIndent(yamlToArm(goldenAnalytic()), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "TestGoldenARM.json", append(b, '\n'))
}

func TestGoldenJSON(t *testing.T) {
	b, err := json.MarshalIndent(yamlToJson(goldenAnalytic()), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "TestGoldenJSON.json", append(b, '\n'))
}

func TestGoldenBicep(t *testing.T) {
	got, err := generateBicepDSL(goldenAnalytic())
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "TestGoldenBicep.bicep", []byte(got))
}
