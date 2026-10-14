package conversion

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

func findingMessages(fs []EntityFinding, level string) string {
	var b strings.Builder
	for _, f := range fs {
		if f.Level == level {
			b.WriteString(f.Message + "\n")
		}
	}
	return b.String()
}

func TestCheckEntities_Warnings(t *testing.T) {
	a := model.Analytic{
		Query: "T | project A = 1",
		EntityMapping: []model.Entities{
			{EntityType: "Account", FieldMapping: []model.FieldMapping{{Identifier: "Name", ColumnName: "A"}}},
			{EntityType: "Account", FieldMapping: []model.FieldMapping{{Identifier: "FullName", ColumnName: "A"}}},
			{EntityType: "Host", FieldMapping: []model.FieldMapping{{Identifier: "HostName", ColumnName: "A"}, {Identifier: "DnsDomain", ColumnName: "A"}}},
			{EntityType: "Process", FieldMapping: []model.FieldMapping{{Identifier: "CommandLine", ColumnName: "A"}}},
			{EntityType: "File", FieldMapping: []model.FieldMapping{{Identifier: "Name", ColumnName: "Missing"}}},
		},
	}
	got := CheckEntities(a, TargetSentinel)
	if e := findingMessages(got, LevelError); e != "" {
		t.Fatalf("unexpected errors: %s", e)
	}
	w := findingMessages(got, LevelWarning)
	for _, want := range []string{
		"only weak identifiers (Name) are mapped for Account",
		"built-in names such as ADMINISTRATOR",
		"identifier FullName is kept for backward compatibility",
		"Process cannot be identified strongly",
		"only weak identifiers (Name) are mapped for File",
		`column "Missing" (identifier Name) is not in the query output`,
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	// The strong Host mapping and the legacy-only Account must not be reported as weak.
	if strings.Contains(w, "weak identifiers (HostName") || strings.Contains(w, "weak identifiers (FullName") {
		t.Errorf("unexpected weak-identifier warning:\n%s", w)
	}
}

func TestCheckEntities_XDRTargetAddsXDRFindings(t *testing.T) {
	a := model.Analytic{
		Query: "DeviceProcessEvents | take 1",
		EntityMapping: []model.Entities{
			{EntityType: "Process", FieldMapping: []model.FieldMapping{{Identifier: "CommandLine", ColumnName: "C"}}},
		},
	}
	sentinel := findingMessages(CheckEntities(a, TargetSentinel), LevelWarning)
	xdr := findingMessages(CheckEntities(a, TargetXDR), LevelWarning)
	if strings.Contains(sentinel, "Defender XDR column") || strings.Contains(sentinel, "ReportId") {
		t.Errorf("Sentinel target reported XDR findings:\n%s", sentinel)
	}
	for _, want := range []string{"identifier CommandLine of Process has no Defender XDR column", "ReportId"} {
		if !strings.Contains(xdr, want) {
			t.Errorf("XDR warnings lack %q:\n%s", want, xdr)
		}
	}
}

func TestQueryOutputColumns(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		want     []string
		complete bool
	}{
		{"project", "T | where x == 1 | project A, B = C + 1, D", []string{"a", "b", "d"}, true},
		{"summarize by", "T | summarize count() by Account, Host = Computer", []string{"count_", "account", "host"}, true},
		{"summarize named agg", "T | summarize N = dcount(x), Last = max(t) by Account", []string{"n", "last", "account"}, true},
		{"by with function arg", "T | summarize arg_max(t, *) by bin(t, 1h)", nil, false},
		{"unnamed aggregate", "T | summarize dcount(x) by A", nil, false},
		{"extend is partial", "T | extend Account = tostring(u)", []string{"account"}, false},
		{"comment and string", "// project X\nT | where s == \"a|b;c\" // trailing | project Y\n| project Z", []string{"z"}, true},
		{"let statement", "let x = T | where a == 1;\nx | project P", []string{"p"}, true},
		{"commas in function", "T | project A = strcat(B, \",\", C), D", []string{"a", "d"}, true},
		{"project-away unknown", "T | project-away X", nil, false},
		{"no pipe", "T", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cols, complete := queryOutputColumns(tt.query)
			if complete != tt.complete {
				t.Errorf("complete = %v, want %v (cols %v)", complete, tt.complete, cols)
			}
			if tt.want == nil {
				return
			}
			var got []string
			for c := range cols {
				got = append(got, c)
			}
			if !sameSet(got, tt.want) {
				t.Errorf("columns = %v, want %v", got, tt.want)
			}
		})
	}
}

func sameSet(a, b []string) bool {
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	return reflect.DeepEqual(filterZero(m), map[string]int{})
}

func filterZero(m map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range m {
		if v != 0 {
			out[k] = v
		}
	}
	return out
}

func TestCheckEntityFiles_ExitCodesAndStrict(t *testing.T) {
	dir := t.TempDir()
	ok := writeFileT(t, dir, "ok.yaml", strings.Replace(validRuleYAML, "%s", "Fine", 1))
	weak := writeFileT(t, dir, "weak.yaml", strings.Replace(strings.Replace(validRuleYAML, "%s", "Weak", 1),
		"identifier: FullName", "identifier: Name", 1))
	bad := writeFileT(t, dir, "bad.yaml", strings.Replace(strings.Replace(validRuleYAML, "%s", "Bad", 1),
		"entity_type: Account", "entity_type: Acount", 1))
	typo := writeFileT(t, dir, "typo.yaml", "name: x\nbogus: 1\n")

	run := func(strict bool, files ...string) (int, string) {
		var out bytes.Buffer
		code := CheckEntityFiles(files, TargetSentinel, strict, &out)
		return code, out.String()
	}

	if code, out := run(false, ok); code != 0 || !strings.Contains(out, "ok") {
		t.Errorf("clean file: code %d\n%s", code, out)
	}
	if code, out := run(false, weak); code != 0 || !strings.Contains(out, "warning") {
		t.Errorf("warnings only: code %d\n%s", code, out)
	}
	if code, _ := run(true, weak); code != 1 {
		t.Errorf("-strict with warnings: code %d, want 1", code)
	}
	if code, out := run(false, bad); code != 1 || !strings.Contains(out, `unknown entity_type "Acount"`) {
		t.Errorf("error file: code %d\n%s", code, out)
	}
	if code, out := run(false, typo); code != 1 || !strings.Contains(out, "error") {
		t.Errorf("undecodable file: code %d\n%s", code, out)
	}
	if code, out := run(false, ok, weak, bad); code != 1 || !strings.Contains(out, "3 file(s) checked") {
		t.Errorf("mixed: code %d\n%s", code, out)
	}
}

func TestConversionsEnforceEntityHardLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString(strings.Replace(validRuleYAML, "%s", "Many", 1))
	for i := 0; i < 11; i++ {
		b.WriteString("  - entity_type: IP\n    field_mapping:\n      - identifier: Address\n        column_name: C\n")
	}
	file := writeFileT(t, t.TempDir(), "many.yaml", b.String())

	for name, conv := range map[string]func(string, string) error{
		"arm": SingleYAMLtoARM, "json": SingleYAMLtoJSON, "bicep": SingleYAMLtoBicep,
		"tofu": SingleYAMLtoTofu, "xdr": SingleYAMLtoXDR,
	} {
		out := filepath.Join(t.TempDir(), "out")
		err := conv(out, file)
		if err == nil || !strings.Contains(err.Error(), "at most 10") {
			t.Errorf("%s: err = %v", name, err)
		}
		if _, statErr := os.Stat(out); statErr == nil {
			t.Errorf("%s: output directory created despite the error", name)
		}
	}
}
