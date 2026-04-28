package model

// ARMTemplate represents an Azure Resource Manager deployment template for
// Sentinel analytics rules.
type ARMTemplate struct {
	Schema         string        `json:"$schema"`
	ContentVersion string        `json:"contentVersion"`
	Parameters    any           `json:"parameters"`
	Resources     []ARMResource `json:"resources"`
}

// ARMResource represents a single resource within an ARM template.
type ARMResource struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	Kind       string        `json:"kind"`
	APIVersion string        `json:"apiVersion"`
	Properties ARMProperties `json:"properties"`
}

// ARMProperties holds the detection rule properties within an ARM resource.
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
	EventGroupingSettings  EventGroupingSettings `json:"eventGroupingSettings"`
	EntityMappings        []ARMEntityMapping   `json:"entityMappings"`
}

// ARMEntityMapping maps an entity type to its field mappings in ARM format.
type ARMEntityMapping struct {
	EntityType    string            `json:"entityType"`
	FieldMappings []ARMFieldMapping `json:"fieldMappings"`
}

// ARMFieldMapping maps an identifier to a column name in ARM format.
type ARMFieldMapping struct {
	Identifier string `json:"identifier"`
	ColumnName string `json:"columnName"`
}