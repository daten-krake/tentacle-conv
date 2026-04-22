package model

// BicepAlertRuleResource represents a Bicep resource definition for a Sentinel
// analytics rule.
type BicepAlertRuleResource struct {
	Name       string              `json:"name"`
	Kind       string              `json:"kind"`
	Properties AlertRuleProperties `json:"properties"`
}

// AlertRuleProperties holds the detection rule properties for a Bicep resource.
type AlertRuleProperties struct {
	DisplayName           string                 `json:"displayName"`
	Description           string                 `json:"description"`
	Severity              string                 `json:"severity"`
	Enabled               bool                   `json:"enabled"`
	Query                 string                 `json:"query"`
	QueryFrequency        string                 `json:"queryFrequency"`
	QueryPeriod           string                 `json:"queryPeriod"`
	TriggerOperator       string                 `json:"triggerOperator"`
	TriggerThreshold      int                    `json:"triggerThreshold"`
	SuppressionDuration   string                 `json:"suppressionDuration"`
	SuppressionEnabled    bool                   `json:"suppressionEnabled"`
	StartTimeUtc          *string                `json:"startTimeUtc,omitempty"`
	Tactics               []string               `json:"tactics"`
	Techniques            []string               `json:"techniques"`
	SubTechniques         []string               `json:"subTechniques"`
	AlertRuleTemplateName string                 `json:"alertRuleTemplateName"`
	IncidentConfiguration IncidentConfiguration  `json:"incidentConfiguration"`
	EventGroupingSettings EventGroupingSettings  `json:"eventGroupingSettings"`
	AlertDetailsOverride  any                    `json:"alertDetailsOverride"`
	CustomDetails         any                    `json:"customDetails"`
	EntityMappings        []BicepEntityMapping   `json:"entityMappings"`
	SentinelEntitiesMappings any                 `json:"sentinelEntitiesMappings"`
	TemplateVersion       string                 `json:"templateVersion"`
}

// BicepEntityMapping maps an entity type to its field mappings in Bicep format.
type BicepEntityMapping struct {
	EntityType    string              `json:"entityType"`
	FieldMappings []BicepFieldMapping `json:"fieldMappings"`
}

// BicepFieldMapping maps an identifier to a column name in Bicep format.
type BicepFieldMapping struct {
	Identifier string `json:"identifier"`
	ColumnName string `json:"columnName"`
}