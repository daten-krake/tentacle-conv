package model

// really needed ?
type BicepAlertRuleResource struct {
	Name       string              `json:"name"`
	Kind       string              `json:"kind"`
	Properties AlertRuleProperties `json:"properties"`
}

type AlertRuleProperties struct {
	DisplayName              string                 `json:"displayName"`
	Description              string                 `json:"description"`
	Severity                 string                 `json:"severity"`
	Enabled                  bool                   `json:"enabled"`
	Query                    string                 `json:"query"`
	QueryFrequency           string                 `json:"queryFrequency"`
	QueryPeriod              string                 `json:"queryPeriod"`
	TriggerOperator          string                 `json:"triggerOperator"`
	TriggerThreshold         int                    `json:"triggerThreshold"`
	SuppressionDuration      string                 `json:"suppressionDuration"`
	SuppressionEnabled       bool                   `json:"suppressionEnabled"`
	StartTimeUtc             *string                `json:"startTimeUtc,omitempty"`
	Tactics                  []string               `json:"tactics"`
	Techniques               []string               `json:"techniques"`
	SubTechniques            []string               `json:"subTechniques"`
	AlertRuleTemplateName    string                 `json:"alertRuleTemplateName"`
	IncidentConfiguration    IncidentConfiguration  `json:"incidentConfiguration"`
	EventGroupingSettings    BEventGroupingSettings `json:"eventGroupingSettings"`
	AlertDetailsOverride     interface{}            `json:"alertDetailsOverride"`
	CustomDetails            interface{}            `json:"customDetails"`
	EntityMappings           []EntityMapping        `json:"entityMappings"`
	SentinelEntitiesMappings interface{}            `json:"sentinelEntitiesMappings"`
	TemplateVersion          string                 `json:"templateVersion"`
}

type BIncidentConfiguration struct {
	CreateIncident        bool                  `json:"createIncident"`
	GroupingConfiguration GroupingConfiguration `json:"groupingConfiguration"`
}

type BGroupingConfiguration struct {
	Enabled              bool     `json:"enabled"`
	ReopenClosedIncident bool     `json:"reopenClosedIncident"`
	LookbackDuration     string   `json:"lookbackDuration"`
	MatchingMethod       string   `json:"matchingMethod"`
	GroupByEntities      []string `json:"groupByEntities"`
	GroupByAlertDetails  []string `json:"groupByAlertDetails"`
	GroupByCustomDetails []string `json:"groupByCustomDetails"`
}

type BEventGroupingSettings struct {
	AggregationKind string `json:"aggregationKind"`
}

type EntityMapping struct {
	EntityType    string         `json:"entityType"`
	FieldMappings []FieldMapping `json:"fieldMappings"`
}

type FieldMapping struct {
	Identifier string `json:"identifier"`
	ColumnName string `json:"columnName"`
}
