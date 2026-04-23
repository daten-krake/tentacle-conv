package model

// SentinelAlertRule represents a Sentinel analytics rule in the REST API format.
type SentinelAlertRule struct {
	Kind       string                 `json:"kind"`
	Properties SentinelRuleProperties `json:"properties"`
}

// SentinelRuleProperties holds the detection rule properties for a Sentinel
// analytics rule.
type SentinelRuleProperties struct {
	DisplayName           string                        `json:"displayName"`
	Description           string                        `json:"description"`
	Severity              string                        `json:"severity"`
	Enabled               bool                          `json:"enabled"`
	Query                 string                        `json:"query"`
	QueryFrequency        string                        `json:"queryFrequency"`
	QueryPeriod           string                        `json:"queryPeriod"`
	TriggerOperator       string                        `json:"triggerOperator"`
	TriggerThreshold      int                           `json:"triggerThreshold"`
	SuppressionDuration   string                        `json:"suppressionDuration"`
	SuppressionEnabled    bool                          `json:"suppressionEnabled"`
	Tactics                []string                      `json:"tactics"`
	Techniques            []string                      `json:"techniques"`
	SubTechniques         []string                      `json:"subTechniques"`
	EntityMappings        []SentinelEntityMapping       `json:"entityMappings"`
	IncidentConfiguration SentinelIncidentConfiguration `json:"incidentConfiguration"`
	EventGroupingSettings SentinelEventGroupingSettings `json:"eventGroupingSettings"`
}

// SentinelEntityMapping maps an entity type to its field mappings in Sentinel
// API format.
type SentinelEntityMapping struct {
	EntityType    string                 `json:"entityType"`
	FieldMappings []SentinelFieldMapping `json:"fieldMappings"`
}

// SentinelFieldMapping maps an identifier to a column name in Sentinel API
// format.
type SentinelFieldMapping struct {
	Identifier string `json:"identifier"`
	ColumnName string `json:"columnName"`
}

// SentinelIncidentConfiguration configures incident creation for Sentinel.
type SentinelIncidentConfiguration struct {
	CreateIncident        bool                          `json:"createIncident"`
	GroupingConfiguration SentinelGroupingConfiguration `json:"groupingConfiguration"`
}

// SentinelGroupingConfiguration controls alert grouping for Sentinel.
type SentinelGroupingConfiguration struct {
	Enabled              bool     `json:"enabled"`
	ReopenClosedIncident bool     `json:"reopenClosedIncident"`
	LookbackDuration     string   `json:"lookbackDuration"`
	MatchingMethod       string   `json:"matchingMethod"`
	GroupByEntities      []string `json:"groupByEntities"`
	GroupByAlertDetails  []string `json:"groupByAlertDetails"`
	GroupByCustomDetails []string `json:"groupByCustomDetails"`
}

// SentinelEventGroupingSettings controls alert aggregation for Sentinel.
type SentinelEventGroupingSettings struct {
	AggregationKind string `json:"aggregationKind"`
}