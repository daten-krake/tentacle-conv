package model

// The Sentinel REST API and the ARM template use the same rule properties, so
// the REST types are aliases of the ARM ones. This keeps both outputs built from
// a single mapping (see conversion.ruleProperties).

// SentinelAlertRule represents a Sentinel analytics rule in the REST API format.
type SentinelAlertRule struct {
	Kind       string                 `json:"kind"`
	Properties SentinelRuleProperties `json:"properties"`
}

// SentinelRuleProperties holds the detection rule properties for a Sentinel
// analytics rule.
type SentinelRuleProperties = ARMProperties

// SentinelEntityMapping maps an entity type to its field mappings in Sentinel
// API format.
type SentinelEntityMapping = ARMEntityMapping

// SentinelFieldMapping maps an identifier to a column name in Sentinel API
// format.
type SentinelFieldMapping = ARMFieldMapping

// SentinelIncidentConfiguration configures incident creation for Sentinel.
type SentinelIncidentConfiguration = IncidentConfiguration

// SentinelGroupingConfiguration controls alert grouping for Sentinel.
type SentinelGroupingConfiguration = GroupingConfiguration

// SentinelEventGroupingSettings controls alert aggregation for Sentinel.
type SentinelEventGroupingSettings = EventGroupingSettings
