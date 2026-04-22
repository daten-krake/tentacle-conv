package model

// IncidentConfiguration configures whether alerts generate incidents and how
// they are grouped.
type IncidentConfiguration struct {
	CreateIncident        bool                  `json:"createIncident" yaml:"createIncident"`
	GroupingConfiguration GroupingConfiguration `json:"groupingConfiguration" yaml:"groupingConfiguration"`
}

// GroupingConfiguration controls how alerts are grouped into incidents.
type GroupingConfiguration struct {
	Enabled              bool     `json:"enabled" yaml:"enabled"`
	ReopenClosedIncident bool     `json:"reopenClosedIncident" yaml:"reopenClosedIncident"`
	LookbackDuration     string   `json:"lookbackDuration" yaml:"lookbackDuration"`
	MatchingMethod       string   `json:"matchingMethod" yaml:"matchingMethod"`
	GroupByEntities      []string `json:"groupByEntities" yaml:"groupByEntities"`
	GroupByAlertDetails  []string `json:"groupByAlertDetails" yaml:"groupByAlertDetails"`
	GroupByCustomDetails []string `json:"groupByCustomDetails" yaml:"groupByCustomDetails"`
}

// EventGroupingSettings controls how multiple alerts are aggregated.
type EventGroupingSettings struct {
	AggregationKind string `json:"aggregationKind" yaml:"aggregationKind"`
}