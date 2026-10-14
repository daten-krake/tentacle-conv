package conversion

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

func TestGenerateTofuHCL_Golden(t *testing.T) {
	got, err := generateTofuHCL(goldenAnalytic())
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "TestGoldenTofu.tf", []byte(got))
}

func TestGenerateTofuHCL_Structure(t *testing.T) {
	a := sampleAnalytic()
	a.ID = "PRI-AAD-07"
	a.Mitre = []model.Mitre{{Tactics: []string{"Execution"}, Techniques: []string{"T1059.001", "T1078"}}}
	got, err := generateTofuHCL(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`resource "azurerm_sentinel_alert_rule_scheduled" "pri_aad_07" {`,
		`name                       = "PRI-AAD-07"`,
		`log_analytics_workspace_id = var.workspace_id`,
		`severity                   = "High"`,
		`techniques                 = ["T1059", "T1078"]`,
		`entity_type = "Account"`,
		`create_incident_enabled = true`,
		`aggregation_method = "AlertPerResult"`,
		"# azurerm_sentinel_alert_rule_scheduled has no sub-technique argument; not applied: T1059.001",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n%s", want, got)
		}
	}
}

func TestTofuResourceLabel(t *testing.T) {
	tests := []struct {
		a    model.Analytic
		want string
	}{
		{model.Analytic{ID: "PRI-AAD-07", Name: "x"}, "pri_aad_07"},
		{model.Analytic{Name: "Files with double.extensions!"}, "files_with_double_extensions"},
		{model.Analytic{ID: "11111111-2222-3333-4444-555555555555"}, "rule_11111111_2222_3333_4444_555555555555"},
		{model.Analytic{Name: "123"}, "rule_123"},
		{model.Analytic{Name: "---"}, "rule"},
	}
	for _, tt := range tests {
		if got := tofuResourceLabel(tt.a); got != tt.want {
			t.Errorf("label(%+v) = %q, want %q", tt.a, got, tt.want)
		}
	}
}

func TestGenerateTofuHCL_Limits(t *testing.T) {
	a := sampleAnalytic()
	a.EntityMapping = nil
	for i := 0; i < 11; i++ {
		a.EntityMapping = append(a.EntityMapping, model.Entities{
			EntityType:   "IP",
			FieldMapping: []model.FieldMapping{{Identifier: "Address", ColumnName: "c"}},
		})
	}
	if _, err := generateTofuHCL(a); err == nil || !strings.Contains(err.Error(), "at most 10") {
		t.Errorf("11 entity mappings: got %v", err)
	}

	a.EntityMapping = []model.Entities{{EntityType: "Account", FieldMapping: []model.FieldMapping{
		{Identifier: "a", ColumnName: "1"}, {Identifier: "b", ColumnName: "2"},
		{Identifier: "c", ColumnName: "3"}, {Identifier: "d", ColumnName: "4"},
	}}}
	if _, err := generateTofuHCL(a); err == nil || !strings.Contains(err.Error(), "at most 3") {
		t.Errorf("4 field mappings: got %v", err)
	}

	a.EntityMapping = []model.Entities{{EntityType: "Account"}}
	if _, err := generateTofuHCL(a); err == nil {
		t.Error("an entity without field mappings should be rejected")
	}
}

func TestHCLQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", `"plain"`},
		{`say "hi"`, `"say \"hi\""`},
		{`C:\dir`, `"C:\\dir"`},
		{"${var.x}", `"$${var.x}"`},
		{"%{if x}", `"%%{if x}"`},
		{"$ and % alone", `"$ and % alone"`},
		{"a\nb\tc\r", `"a\nb\tc\r"`},
		{"\x01", `"\u0001"`},
	}
	for _, tt := range tests {
		if got := hclQuote(tt.in); got != tt.want {
			t.Errorf("hclQuote(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestHCLQuery_Forms(t *testing.T) {
	tests := []struct {
		name, in, prefix string
	}{
		{"single line", "print 1", `"print 1"`},
		{"multi line", "a\nb", "chomp(<<KQL\n"},
		{"multi line with trailing newline", "a\nb\n", "<<KQL\n"},
		{"crlf falls back", "a\r\nb", `"a\r\nb"`},
		{"leading newline falls back", "\na", `"\na"`},
		{"delimiter taken", "a\nKQL\nb", "chomp(<<KQL_1\n"},
	}
	for _, tt := range tests {
		if got := hclQuery(tt.in); !strings.HasPrefix(got, tt.prefix) {
			t.Errorf("%s: hclQuery = %q, want prefix %q", tt.name, got, tt.prefix)
		}
	}
}

// tofuBinary returns the OpenTofu or Terraform executable, or "" if neither is
// installed.
func tofuBinary() string {
	for _, name := range []string{"tofu", "terraform"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// The expressions produced by hclQuote and hclQuery are evaluated by a real
// OpenTofu/Terraform and must yield exactly the original strings.
func TestHCLEscaping_EvaluatesToOriginal(t *testing.T) {
	bin := tofuBinary()
	if bin == "" {
		t.Skip("neither tofu nor terraform is installed")
	}

	inputs := append([]string{}, escapeSeeds...)
	inputs = append(inputs,
		"$${x}", "$$${x}", "%%{x}", "a\n${b}\n%{c}\n", "KQL", "x\nKQL\ny", "trailing\n", "\n\n",
		"let x = 'a';\nT | where y == \"b\\c\"\n| take 1",
	)
	// The NUL byte is not representable in a Terraform string.
	var cases []string
	for _, s := range inputs {
		if !strings.Contains(s, "\x00") {
			cases = append(cases, s)
		}
	}

	var cfg strings.Builder
	for i, s := range cases {
		fmt.Fprintf(&cfg, "output \"quote_%d\" {\n  value = %s\n}\n\n", i, hclQuote(s))
		fmt.Fprintf(&cfg, "output \"query_%d\" {\n  value = %s\n}\n\n", i, hclQuery(s))
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(cfg.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", filepath.Base(bin), strings.Join(args, " "), err, out)
		}
		return out
	}
	run("init", "-input=false", "-no-color")
	run("apply", "-auto-approve", "-input=false", "-no-color")
	raw := run("output", "-json")

	var outputs map[string]struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &outputs); err != nil {
		t.Fatalf("parsing output: %v\n%s", err, raw)
	}
	for i, s := range cases {
		for _, kind := range []string{"quote", "query"} {
			key := fmt.Sprintf("%s_%d", kind, i)
			got, ok := outputs[key]
			if !ok {
				t.Errorf("%s: no output for %q", key, s)
			} else if got.Value != s {
				t.Errorf("%s: %q evaluated to %q", key, s, got.Value)
			}
		}
	}
}

func TestSingleYAMLtoTofu_WritesFilesAndKeepsExistingScaffold(t *testing.T) {
	out := filepath.Join(t.TempDir(), "tf")
	if err := SingleYAMLtoTofu(out, ruleFile(t, "My_Rule")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"My_Rule.tf", "versions.tf", "variables.tf"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}

	// A user-edited scaffold file is never overwritten.
	custom := filepath.Join(out, "variables.tf")
	if err := os.WriteFile(custom, []byte("# mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SingleYAMLtoTofu(out, ruleFile(t, "Other_Rule")); err != nil {
		t.Fatal(err)
	}
	if got := string(readFileT(t, custom)); got != "# mine\n" {
		t.Errorf("variables.tf was overwritten: %q", got)
	}
}
