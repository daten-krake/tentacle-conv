package conversion

import (
	"crypto/sha1"
	"fmt"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

// Settings prodyaml does not model. They are applied identically to the ARM,
// REST API and Bicep outputs; change them here only.
const (
	ruleKind                = "Scheduled"
	ruleAPIVersion          = "2023-12-01-preview"
	ruleEnabled             = true
	ruleTriggerOperator     = "GreaterThan"
	ruleTriggerThreshold    = 0
	ruleSuppressionEnabled  = false
	ruleSuppressionDuration = "PT5H"
	ruleCreateIncident      = true
	ruleGroupingEnabled     = true
	ruleGroupingLookback    = "P7D"
	ruleGroupingMatching    = "AllEntities"
	ruleAggregationKind     = "AlertPerResult"
)

// ruleIDNamespace is the UUIDv5 namespace used to derive a stable rule ID from
// the rule name when prodyaml has no id. It must never change, or rules
// without an id would be redeployed under new IDs.
var ruleIDNamespace = [16]byte{
	0x7c, 0x1d, 0x5e, 0x0a, 0x3b, 0x94, 0x4f, 0x6e,
	0x9a, 0x21, 0xd4, 0x58, 0x0b, 0x6c, 0x83, 0xf1,
}

// ruleID returns the resource name of the rule: the prodyaml id when set,
// otherwise a deterministic UUIDv5 of the rule name. Using an ID that does not
// depend on the display name means renaming a rule updates it in place.
func ruleID(a model.Analytic) string {
	if a.ID != "" {
		return a.ID
	}
	return uuidV5(ruleIDNamespace, a.Name)
}

// uuidV5 returns the RFC 4122 version 5 (SHA-1, name based) UUID of name in
// the given namespace.
func uuidV5(namespace [16]byte, name string) string {
	h := sha1.New()
	h.Write(namespace[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)

	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant

	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// ruleProperties maps a prodyaml Analytic to the rule properties shared by the
// ARM template and the REST API. All slices are non-nil so they serialize as
// [] rather than null.
func ruleProperties(a model.Analytic) model.ARMProperties {
	return model.ARMProperties{
		DisplayName:         a.Name,
		Description:         a.Description,
		Severity:            a.Severity,
		Enabled:             ruleEnabled,
		Query:               a.Query,
		QueryFrequency:      a.QueryFrequency,
		QueryPeriod:         a.QueryPeriod,
		TriggerOperator:     ruleTriggerOperator,
		TriggerThreshold:    ruleTriggerThreshold,
		SuppressionDuration: ruleSuppressionDuration,
		SuppressionEnabled:  ruleSuppressionEnabled,
		Tactics:             extractTactics(a.Mitre),
		Techniques:          extractTechniques(a.Mitre),
		SubTechniques:       extractSubTechniques(a.Mitre),
		IncidentConfiguration: model.IncidentConfiguration{
			CreateIncident: ruleCreateIncident,
			GroupingConfiguration: model.GroupingConfiguration{
				Enabled:              ruleGroupingEnabled,
				LookbackDuration:     ruleGroupingLookback,
				MatchingMethod:       ruleGroupingMatching,
				GroupByEntities:      []string{},
				GroupByAlertDetails:  []string{},
				GroupByCustomDetails: []string{},
			},
		},
		EventGroupingSettings: model.EventGroupingSettings{
			AggregationKind: ruleAggregationKind,
		},
		EntityMappings: buildARMEntityMappings(a.EntityMapping),
	}
}
