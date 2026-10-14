package conversion

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

func TestUUIDv5_KnownVector(t *testing.T) {
	// RFC 4122 DNS namespace + "www.example.com" -> 2ed6657d-e927-568b-95e1-2665a8aea6a2
	dns := [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	if got, want := uuidV5(dns, "www.example.com"), "2ed6657d-e927-568b-95e1-2665a8aea6a2"; got != want {
		t.Errorf("uuidV5 = %s, want %s", got, want)
	}
}

func TestRuleID(t *testing.T) {
	a := model.Analytic{Name: "My rule"}
	first := ruleID(a)
	if first != ruleID(a) {
		t.Error("fallback ID must be deterministic")
	}
	if first == ruleID(model.Analytic{Name: "Other rule"}) {
		t.Error("different names must give different IDs")
	}
	if len(first) != 36 {
		t.Errorf("fallback ID %q is not a GUID", first)
	}
	if got := ruleID(model.Analytic{ID: "PRI-AAD-07", Name: "My rule"}); got != "PRI-AAD-07" {
		t.Errorf("explicit id not used: %q", got)
	}
}

func TestRuleIDIsIndependentOfDisplayNameWhenSet(t *testing.T) {
	a := yamlToArm(model.Analytic{ID: "X-1", Name: "Before"})
	b := yamlToArm(model.Analytic{ID: "X-1", Name: "After"})
	if a.Resources[0].Name != b.Resources[0].Name || a.Resources[0].ID != b.Resources[0].ID {
		t.Error("renaming a rule must not change its resource name/id")
	}
}

func TestARMExpressionsEscapeQuotes(t *testing.T) {
	if got := createARMName("it's"); !strings.Contains(got, "it''s") {
		t.Errorf("createARMName = %q, quote not doubled", got)
	}
	if got := createARMId("it's"); !strings.Contains(got, "it''s") {
		t.Errorf("createARMId = %q, quote not doubled", got)
	}
}

// ARM and REST output must carry identical rule properties (#9).
func TestJSONAndARMProperties_Agree(t *testing.T) {
	a := sampleAnalytic()
	arm := yamlToArm(a).Resources[0].Properties
	api := yamlToJson(a)

	if api.Kind != "Scheduled" {
		t.Errorf("Kind = %q", api.Kind)
	}
	if !reflect.DeepEqual(arm, api.Properties) {
		t.Errorf("properties differ:\narm: %+v\napi: %+v", arm, api.Properties)
	}
	if len(api.Properties.EntityMappings) != 1 {
		t.Error("entity mappings must be present in JSON output")
	}
	ic := api.Properties.IncidentConfiguration
	if !ic.CreateIncident || ic.GroupingConfiguration.LookbackDuration == "" ||
		ic.GroupingConfiguration.MatchingMethod == "" || api.Properties.EventGroupingSettings.AggregationKind == "" {
		t.Errorf("incident/grouping defaults missing: %+v", api.Properties)
	}
}

// No collection may serialise as JSON null (#23).
func TestOutputHasNoNullArrays(t *testing.T) {
	a := model.Analytic{Name: "Minimal"}
	for name, v := range map[string]any{"arm": yamlToArm(a), "json": yamlToJson(a)} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "null") {
			t.Errorf("%s output contains null: %s", name, b)
		}
	}
}

func TestExtractTechniques_SubTechniques(t *testing.T) {
	mitre := []model.Mitre{
		{Techniques: []string{"T1059.001", "T1078"}},
		{Techniques: []string{"T1059.003", "T1059", "T1059.001"}},
	}
	if got, want := extractTechniques(mitre), []string{"T1059", "T1078"}; !reflect.DeepEqual(got, want) {
		t.Errorf("techniques = %v, want %v", got, want)
	}
	if got, want := extractSubTechniques(mitre), []string{"T1059.001", "T1059.003"}; !reflect.DeepEqual(got, want) {
		t.Errorf("subTechniques = %v, want %v", got, want)
	}
	if got := extractSubTechniques(nil); got == nil || len(got) != 0 {
		t.Errorf("subTechniques of nothing should be an empty slice, got %#v", got)
	}
}

func TestMergeTechniques(t *testing.T) {
	tests := []struct {
		name       string
		tech, subs []string
		want       []string
	}{
		{"no subs", []string{"T1078", "T1098"}, nil, []string{"T1078", "T1098"}},
		{"parent implied by sub is dropped", []string{"T1059", "T1078"}, []string{"T1059.001"}, []string{"T1078", "T1059.001"}},
		{"legacy dotted ids in techniques", []string{"T1059.001"}, nil, []string{"T1059.001"}},
		{"duplicates removed", []string{"T1059.001"}, []string{"T1059.001"}, []string{"T1059.001"}},
		{"nothing", nil, nil, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeTechniques(tt.tech, tt.subs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeTechniques = %v, want %v", got, tt.want)
			}
		})
	}
}

// prodyaml -> ARM -> prodyaml must keep technique IDs (#16).
func TestTechniquesRoundTrip(t *testing.T) {
	in := model.Analytic{ID: "R-1", Name: "R", Mitre: []model.Mitre{
		{Tactics: []string{"Execution"}, Techniques: []string{"T1059.001", "T1078"}},
	}}
	res := yamlToArm(in).Resources[0]
	res.Type, res.Kind = ARMRuleType, "Scheduled"
	back := armToAnalytic(res)

	if got, want := back.Mitre[0].Techniques, []string{"T1078", "T1059.001"}; !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip techniques = %v, want %v", got, want)
	}
	if back.ID != "R-1" {
		t.Errorf("round-trip ID = %q, want R-1", back.ID)
	}
	if !reflect.DeepEqual(yamlToArm(back).Resources[0].Properties.SubTechniques, []string{"T1059.001"}) {
		t.Error("second forward conversion changed subTechniques")
	}
}

func TestRuleIDOf(t *testing.T) {
	tests := map[string]string{
		"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/PRI-AAD-07')]": "PRI-AAD-07",
		"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/ab12-cd')]":   "ab12-cd",
		"11111111-2222-3333-4444-555555555555":                                       "11111111-2222-3333-4444-555555555555",
		"my-workspace/Microsoft.SecurityInsights/RULE-9":                             "RULE-9",
		"[variables('ruleName')]":                                                    "",
		"":                                                                           "",
	}
	for name, want := range tests {
		if got := ruleIDOf(model.ARMResource{Name: name}); got != want {
			t.Errorf("ruleIDOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestNotScheduledRule(t *testing.T) {
	ok := model.ARMResource{Type: ARMRuleType, Kind: "Scheduled"}
	if r := notScheduledRule(ok); r != "" {
		t.Errorf("scheduled rule rejected: %s", r)
	}
	// Newer exports use the Microsoft.SecurityInsights resource provider.
	if r := notScheduledRule(model.ARMResource{Type: "Microsoft.SecurityInsights/alertRules", Kind: "scheduled"}); r != "" {
		t.Errorf("SecurityInsights scheduled rule rejected: %s", r)
	}
	for _, kind := range []string{"NRT", "Fusion", "MLBehaviorAnalytics", "MicrosoftSecurityIncidentCreation", ""} {
		if notScheduledRule(model.ARMResource{Type: ARMRuleType, Kind: kind}) == "" {
			t.Errorf("kind %q should be skipped", kind)
		}
	}
	if notScheduledRule(model.ARMResource{Type: "Microsoft.OperationalInsights/workspaces/providers/metadata", Kind: "Scheduled"}) == "" {
		t.Error("metadata resources should be skipped")
	}
}
