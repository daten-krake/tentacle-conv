package model

import (
	"strings"
	"testing"
)

func mapping(entityType string, ids ...string) Entities {
	e := Entities{EntityType: entityType}
	for _, id := range ids {
		e.FieldMapping = append(e.FieldMapping, FieldMapping{Identifier: id, ColumnName: "Col" + id})
	}
	return e
}

func issueMessages(a Analytic) string {
	var b strings.Builder
	for _, i := range a.EntityMappingIssues() {
		b.WriteString(i.Message + "\n")
	}
	return b.String()
}

func TestEntityMappingIssues_Valid(t *testing.T) {
	a := Analytic{EntityMapping: []Entities{
		mapping("Account", "Name", "UPNSuffix", "AadUserId"),
		mapping("Host", "HostName", "DnsDomain"),
		mapping("IP", "Address"),
		mapping("IP", "Address"), // the same type may be mapped twice
	}}
	if got := issueMessages(a); got != "" {
		t.Errorf("unexpected issues:\n%s", got)
	}
}

func TestEntityMappingIssues(t *testing.T) {
	tests := []struct {
		name string
		a    Analytic
		want string
	}{
		{"unknown type", Analytic{EntityMapping: []Entities{mapping("Hostname", "HostName")}}, `unknown entity_type "Hostname"`},
		{"case hint", Analytic{EntityMapping: []Entities{mapping("host", "HostName")}}, `did you mean "Host"`},
		{"bad identifier", Analytic{EntityMapping: []Entities{mapping("File", "Path")}}, `identifier "Path" is not valid for File`},
		{"four identifiers", Analytic{EntityMapping: []Entities{mapping("Account", "Name", "NTDomain", "DnsDomain", "UPNSuffix")}}, "4 field_mapping entries"},
		{"no identifiers", Analytic{EntityMapping: []Entities{{EntityType: "Host"}}}, "no field_mapping"},
		{"duplicate identifier", Analytic{EntityMapping: []Entities{mapping("Host", "HostName", "HostName")}}, "mapped more than once"},
		{"empty column", Analytic{EntityMapping: []Entities{{EntityType: "IP", FieldMapping: []FieldMapping{{Identifier: "Address"}}}}}, "empty column_name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := issueMessages(tt.a); !strings.Contains(got, tt.want) {
				t.Errorf("issues %q do not contain %q", got, tt.want)
			}
		})
	}

	t.Run("eleven mappings", func(t *testing.T) {
		a := Analytic{}
		for i := 0; i < 11; i++ {
			a.EntityMapping = append(a.EntityMapping, mapping("IP", "Address"))
		}
		issues := a.EntityMappingIssues()
		if len(issues) != 1 || issues[0].Index != -1 || !strings.Contains(issues[0].Message, "at most 10") {
			t.Errorf("issues = %+v", issues)
		}
	})
}

func TestValidateIncludesEntityIssues(t *testing.T) {
	a := validAnalytic()
	a.EntityMapping = []Entities{mapping("Hostname", "HostName")}
	err := a.Validate()
	if err == nil || !strings.Contains(err.Error(), "entity_mapping[0] (Hostname)") {
		t.Errorf("Validate() = %v", err)
	}
}

func TestEntitySpecStrength(t *testing.T) {
	acct := SentinelEntities["Account"]
	tests := []struct {
		ids  []string
		want bool
	}{
		{[]string{"Name"}, false},
		{[]string{"FullName"}, false},
		{[]string{"Name", "UPNSuffix"}, true},
		{[]string{"AadUserId"}, true},
		{[]string{"Name", "NTDomain"}, true},
		{[]string{"NTDomain"}, false},
	}
	for _, tt := range tests {
		if got := acct.IsStrong(tt.ids); got != tt.want {
			t.Errorf("Account %v strong = %v, want %v", tt.ids, got, tt.want)
		}
	}
	if SentinelEntities["SubmissionMail"].IsStrong([]string{"SubmissionId", "NetworkMessageId", "Recipient"}) {
		t.Error("SubmissionMail needs four identifiers and can never be strong with three")
	}
}
