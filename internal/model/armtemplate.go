package model

type ARMTemplate struct {
	Schema         string        `json:"$schema"`
	ContentVersion string        `json:"contentVersion"`
	Parameters     interface{}   `json:"parameters"`
	Resources      []ARMResource `json:"resources"`
}

type ARMResource struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	Kind       string        `json:"kind"`
	APIVersion string        `json:"apiVersion"`
	Properties ARMProperties `json:"properties"`
}

type ARMProperties struct {
	DisplayName           string                `json:"displayName"`
	Description           string                `json:"description"`
	Severity              string                `json:"severity"`
	Enabled               bool                  `json:"enabled"`
	Query                 string                `json:"query"`
	QueryFrequency        string                `json:"queryFrequency"`
	QueryPeriod           string                `json:"queryPeriod"`
	TriggerOperator       string                `json:"triggerOperator"`
	TriggerThreshold      int                   `json:"triggerThreshold"`
	SuppressionDuration   string                `json:"suppressionDuration"`
	SuppressionEnabled    bool                  `json:"suppressionEnabled"`
	Tactics               []string              `json:"tactics"`
	Techniques            []string              `json:"techniques"`
	SubTechniques         []string              `json:"subTechniques"`
	IncidentConfiguration IncidentConfiguration `json:"incidentConfiguration"`
	EventGroupingSettings EventGroupingSettings `json:"eventGroupingSettings"`
	EntityMappings        []ARMEntityMapping    `json:"entityMappings"`
}

type IncidentConfiguration struct {
	CreateIncident        bool                  `json:"createIncident"`
	GroupingConfiguration GroupingConfiguration `json:"groupingConfiguration"`
}

type GroupingConfiguration struct {
	Enabled              bool     `json:"enabled"`
	ReopenClosedIncident bool     `json:"reopenClosedIncident"`
	LookbackDuration     string   `json:"lookbackDuration"`
	MatchingMethod       string   `json:"matchingMethod"`
	GroupByEntities      []string `json:"groupByEntities"`
	GroupByAlertDetails  []string `json:"groupByAlertDetails"`
	GroupByCustomDetails []string `json:"groupByCustomDetails"`
}

type EventGroupingSettings struct {
	AggregationKind string `json:"aggregationKind"`
}

type ARMEntityMapping struct {
	EntityType    string            `json:"entityType"`
	FieldMappings []ARMFieldMapping `json:"fieldMappings"`
}

type ARMFieldMapping struct {
	Identifier string `json:"identifier"`
	ColumnName string `json:"columnName"`
}
