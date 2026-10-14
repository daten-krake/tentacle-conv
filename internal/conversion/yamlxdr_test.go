package conversion

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

func xdrAnalytic() model.Analytic {
	a := goldenAnalytic()
	a.State = "prod"
	a.ResponsePlan = "Isolate the host."
	a.QueryFrequency = "PT1H"
	a.QueryPeriod = "PT4H"
	a.Query = "DeviceProcessEvents\n| project Timestamp, DeviceId, ReportId, DeviceName, AccountName"
	return a
}

func hasWarning(ws []string, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestYamlToXDR_Fields(t *testing.T) {
	a := xdrAnalytic()
	rule, warnings, err := yamlToXDR(a)
	if err != nil {
		t.Fatal(err)
	}
	if rule.ODataType != "#microsoft.graph.security.detectionRule" {
		t.Errorf("@odata.type = %q", rule.ODataType)
	}
	if rule.ID != "EVA-MDFE-01" {
		t.Errorf("id = %q", rule.ID)
	}
	if rule.Status != "enabled" {
		t.Errorf("status = %q", rule.Status)
	}
	at := rule.DetectionAction.AlertTemplate
	if at.Severity != "medium" {
		t.Errorf("severity = %q, want lowercase", at.Severity)
	}
	if at.Title != a.Name || rule.DisplayName != a.Name {
		t.Errorf("title/displayName not taken from name")
	}
	if at.RecommendedActions != "Isolate the host." {
		t.Errorf("recommendedActions = %q", at.RecommendedActions)
	}
	if rule.QueryCondition.QueryText != a.Query || rule.Schedule.Frequency != "PT1H" {
		t.Errorf("query/schedule not mapped: %+v %+v", rule.QueryCondition, rule.Schedule)
	}
	if hasWarning(warnings, "query_period") || hasWarning(warnings, "ReportId") {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestYamlToXDR_IDFallbackAndStatus(t *testing.T) {
	a := xdrAnalytic()
	a.ID = ""
	a.Name = "Suspicious  PowerShell / Office!"
	a.State = ""
	rule, warnings, err := yamlToXDR(a)
	if err != nil {
		t.Fatal(err)
	}
	if rule.ID != "suspicious-powershell-office" {
		t.Errorf("id = %q", rule.ID)
	}
	if rule.Status != "disabled" || !hasWarning(warnings, "disabled") {
		t.Errorf("status = %q, warnings = %v", rule.Status, warnings)
	}

	a.Name = "!!!"
	if _, _, err := yamlToXDR(a); err == nil {
		t.Error("a name without usable characters and no id must be an error")
	}
}

func TestYamlToXDR_Frequency(t *testing.T) {
	tests := []struct {
		freq, period string
		wantErr      bool
		wantWarn     string
	}{
		{"PT1H", "PT4H", false, ""},
		{"PT1H", "P1D", false, "lookback is fixed at PT4H"},
		{"P1D", "P30D", false, ""},
		{"PT12H", "PT48H", false, ""},
		{"PT20M", "PT20M", false, "custom frequency"},
		{"PT1M", "PT1M", true, ""},
		{"P15D", "P15D", true, ""},
		{"nonsense", "PT1H", true, ""},
	}
	for _, tt := range tests {
		a := xdrAnalytic()
		a.QueryFrequency, a.QueryPeriod = tt.freq, tt.period
		_, warnings, err := yamlToXDR(a)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tt.freq, err, tt.wantErr)
			continue
		}
		if tt.wantWarn != "" && !hasWarning(warnings, tt.wantWarn) {
			t.Errorf("%s/%s: warnings %v lack %q", tt.freq, tt.period, warnings, tt.wantWarn)
		}
		if tt.wantWarn == "" && !tt.wantErr && (hasWarning(warnings, "custom frequency") || hasWarning(warnings, "lookback")) {
			t.Errorf("%s/%s: unexpected warnings %v", tt.freq, tt.period, warnings)
		}
	}
}

func TestParseISODuration(t *testing.T) {
	tests := map[string]time.Duration{
		"PT5M": 5 * time.Minute, "PT1H": time.Hour, "P1D": 24 * time.Hour, "P1DT12H": 36 * time.Hour,
		"P2W": 14 * 24 * time.Hour, "PT90S": 90 * time.Second,
	}
	for in, want := range tests {
		if got, err := parseISODuration(in); err != nil || got != want {
			t.Errorf("parseISODuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "P", "PT", "1H", "P1X", "PT1.5H"} {
		if _, err := parseISODuration(bad); err == nil {
			t.Errorf("parseISODuration(%q) should fail", bad)
		}
	}
}

func TestBuildXDREntityMappings(t *testing.T) {
	input := []model.Entities{
		{EntityType: "Account", FieldMapping: []model.FieldMapping{
			{Identifier: "Name", ColumnName: "AccountName"},
			{Identifier: "UPNSuffix", ColumnName: "AccountUPNSuffix"},
			{Identifier: "AadUserId", ColumnName: "AccountObjectId"},
		}},
		{EntityType: "Account", FieldMapping: []model.FieldMapping{{Identifier: "FullName", ColumnName: "InitiatingUserPrincipalName"}}},
		{EntityType: "Host", FieldMapping: []model.FieldMapping{{Identifier: "HostName", ColumnName: "DeviceName"}, {Identifier: "DnsDomain", ColumnName: "Domain"}}},
		{EntityType: "IP", FieldMapping: []model.FieldMapping{{Identifier: "Address", ColumnName: "SrcIp"}}},
		{EntityType: "IP", FieldMapping: []model.FieldMapping{{Identifier: "Address", ColumnName: "DstIp"}}},
		{EntityType: "Process", FieldMapping: []model.FieldMapping{{Identifier: "CommandLine", ColumnName: "ProcessCommandLine"}}},
		{EntityType: "Malware", FieldMapping: []model.FieldMapping{{Identifier: "Name", ColumnName: "M"}}},
		{EntityType: "File", FieldMapping: []model.FieldMapping{{Identifier: "Name", ColumnName: "FileName"}, {Identifier: "Directory", ColumnName: "FolderPath"}}},
	}
	got, warnings := buildXDREntityMappings(input)

	want := model.EntityMappingConfiguration{
		"accounts": {
			{"nameColumn": "AccountName", "upnSuffixColumn": "AccountUPNSuffix", "aadUserIdColumn": "AccountObjectId"},
			{"upnColumn": "InitiatingUserPrincipalName"},
		},
		"hosts": {{"nameColumn": "DeviceName", "dnsDomainColumn": "Domain"}},
		"ips":   {{"addressColumn": "SrcIp"}, {"addressColumn": "DstIp"}},
		"files": {{"nameColumn": "FileName"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mappings =\n%v\nwant\n%v", got, want)
	}

	for _, sub := range []string{
		"FullName of Account is mapped to upnColumn",
		"identifier CommandLine of Process has no Defender XDR column",
		"no identifier of Process could be mapped",
		`entity type "Malware" has no Defender XDR equivalent`,
		"identifier Directory of File has no Defender XDR column",
		"2 accounts mappings",
	} {
		if !hasWarning(warnings, sub) {
			t.Errorf("warnings lack %q:\n%s", sub, strings.Join(warnings, "\n"))
		}
	}
}

func TestBuildXDRTactics(t *testing.T) {
	mitre := []model.Mitre{
		{Tactics: []string{"Execution", "Persistence"}, Techniques: []string{"T1059.001", "T1059.003", "T1078"}},
		{Tactics: []string{"Execution"}, Techniques: []string{"T1059.001", "T1204"}},
	}
	got, warnings := buildXDRTactics(mitre)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "mitre[0]") || !strings.Contains(warnings[0], "one mitre entry per tactic") {
		t.Errorf("expected one ambiguity warning for mitre[0], got %v", warnings)
	}
	want := []model.MitreTactic{
		{Tactic: "Execution", Techniques: []model.MitreTechnique{
			{Technique: "T1059", SubTechniques: []string{"T1059.001", "T1059.003"}},
			{Technique: "T1078"},
			{Technique: "T1204"},
		}},
		{Tactic: "Persistence", Techniques: []model.MitreTechnique{
			{Technique: "T1059", SubTechniques: []string{"T1059.001", "T1059.003"}},
			{Technique: "T1078"},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tactics =\n%+v\nwant\n%+v", got, want)
	}
}

func TestBuildXDRTactics_OneEntryPerTacticIsUnambiguous(t *testing.T) {
	mitre := []model.Mitre{
		{Tactics: []string{"DefenseEvasion"}, Techniques: []string{"T1036"}},
		{Tactics: []string{"InitialAccess"}, Techniques: []string{"T1078"}},
		{Tactics: []string{"Discovery", "Collection"}}, // no techniques: nothing to pair
	}
	got, warnings := buildXDRTactics(mitre)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	want := []model.MitreTactic{
		{Tactic: "DefenseEvasion", Techniques: []model.MitreTechnique{{Technique: "T1036"}}},
		{Tactic: "InitialAccess", Techniques: []model.MitreTechnique{{Technique: "T1078"}}},
		{Tactic: "Discovery"},
		{Tactic: "Collection"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tactics =\n%+v\nwant\n%+v", got, want)
	}
}

func TestYamlToXDR_QueryLint(t *testing.T) {
	a := xdrAnalytic()
	a.Query = "DeviceEvents | where Timestamp > ago(1d) | summarize count() by DeviceId"
	a.Description = "<b>bold</b> text"
	_, warnings, err := yamlToXDR(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"ReportId", "ago()", "HTML"} {
		if !hasWarning(warnings, sub) {
			t.Errorf("warnings lack %q: %v", sub, warnings)
		}
	}
}

// Properties Microsoft removed on 2026-10-01 must never be emitted.
func TestXDROutputHasNoRemovedProperties(t *testing.T) {
	rule, _, err := yamlToXDR(xdrAnalytic())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	removed := map[string]bool{
		"isEnabled": true, "period": true, "category": true, "impactedAssets": true,
		"mitreTechniques": true, "responseActions": true, "detectorId": true,
		"lastRunDetails": true, "nextRunDateTime": true, "lastModifiedDateTime": true,
	}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if removed[k] {
					t.Errorf("removed property %q at %s", k, path)
				}
				walk(child, path+"."+k)
			}
		case []any:
			for _, child := range x {
				walk(child, path+"[]")
			}
		}
	}
	walk(doc, "$")
}

func TestGoldenXDR(t *testing.T) {
	rule, _, err := yamlToXDR(xdrAnalytic())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "TestGoldenXDR.json", append(b, '\n'))
}

func TestSingleYAMLtoXDR_WritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "xdr")
	if err := SingleYAMLtoXDR(out, ruleFile(t, "My_Rule")); err != nil {
		t.Fatal(err)
	}
	var rule model.DetectionRule
	if err := json.Unmarshal(readFileT(t, filepath.Join(out, "My_Rule.json")), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.ID != "ABC-01" || rule.Status != "disabled" {
		t.Errorf("unexpected rule %+v", rule)
	}
	if _, err := os.Stat(filepath.Join(out, "My_Rule.json")); err != nil {
		t.Error(err)
	}
}
