package model

type SentinelAlertRule struct {
	Kind       string                 `json:"kind"`
	Properties SentinelRuleProperties `json:"properties"`
}

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
	Tactics               []string                      `json:"tactics"`
	Techniques            []string                      `json:"techniques"`
	SubTechniques         []string                      `json:"subTechniques"`
	EntityMappings        []SentinelEntityMapping       `json:"entityMappings"`
	IncidentConfiguration SentinelIncidentConfiguration `json:"incidentConfiguration"`
	EventGroupingSettings SentinelEventGroupingSettings `json:"eventGroupingSettings"`
}

type SentinelEntityMapping struct {
	EntityType    string                 `json:"entityType"`
	FieldMappings []SentinelFieldMapping `json:"fieldMappings"`
}

type SentinelFieldMapping struct {
	Identifier string `json:"identifier"`
	ColumnName string `json:"columnName"`
}

type SentinelIncidentConfiguration struct {
	CreateIncident        bool                          `json:"createIncident"`
	GroupingConfiguration SentinelGroupingConfiguration `json:"groupingConfiguration"`
}

type SentinelGroupingConfiguration struct {
	Enabled              bool     `json:"enabled"`
	ReopenClosedIncident bool     `json:"reopenClosedIncident"`
	LookbackDuration     string   `json:"lookbackDuration"`
	MatchingMethod       string   `json:"matchingMethod"`
	GroupByEntities      []string `json:"groupByEntities"`
	GroupByAlertDetails  []string `json:"groupByAlertDetails"`
	GroupByCustomDetails []string `json:"groupByCustomDetails"`
}

type SentinelEventGroupingSettings struct {
	AggregationKind string `json:"aggregationKind"`
}
