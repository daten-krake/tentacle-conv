package model

// DetectionRule is a Microsoft Defender XDR custom detection rule in the shape
// accepted by POST https://graph.microsoft.com/beta/security/rules/detectionRules.
//
// Properties Microsoft removed on 2026-10-01 (isEnabled, schedule.period,
// alertTemplate.category/impactedAssets/mitreTechniques, responseActions,
// detectorId, lastRunDetails) are deliberately absent.
type DetectionRule struct {
	ODataType       string          `json:"@odata.type"`
	ID              string          `json:"id"`
	DisplayName     string          `json:"displayName"`
	Description     string          `json:"description,omitempty"`
	Status          string          `json:"status"`
	QueryCondition  QueryCondition  `json:"queryCondition"`
	Schedule        RuleSchedule    `json:"schedule"`
	DetectionAction DetectionAction `json:"detectionAction"`
}

// QueryCondition holds the advanced hunting query.
type QueryCondition struct {
	QueryText string `json:"queryText"`
}

// RuleSchedule says how often the rule runs (ISO 8601 duration).
type RuleSchedule struct {
	Frequency string `json:"frequency"`
}

// DetectionAction describes the alert that is created and how it is
// correlated into incidents.
type DetectionAction struct {
	AlertTemplate         AlertTemplate            `json:"alertTemplate"`
	IncidentConfiguration XDRIncidentConfiguration `json:"incidentConfiguration"`
}

// AlertTemplate defines the alert generated for a detection.
type AlertTemplate struct {
	Title              string                     `json:"title"`
	Description        string                     `json:"description,omitempty"`
	Severity           string                     `json:"severity"`
	RecommendedActions string                     `json:"recommendedActions,omitempty"`
	EntityMappings     EntityMappingConfiguration `json:"entityMappings,omitempty"`
	Tactics            []MitreTactic              `json:"tactics,omitempty"`
}

// EntityMappingConfiguration maps an XDR entity collection (accounts, hosts,
// ips, ...) to its mappings. Each mapping object holds the *Column properties
// of that entity type, so a column is only present when it is mapped.
type EntityMappingConfiguration map[string][]map[string]string

// MitreTactic nests the techniques used within one tactic.
type MitreTactic struct {
	Tactic     string           `json:"tactic"`
	Techniques []MitreTechnique `json:"techniques,omitempty"`
}

// MitreTechnique is a parent technique with its sub-techniques.
type MitreTechnique struct {
	Technique     string   `json:"technique"`
	SubTechniques []string `json:"subTechniques,omitempty"`
}

// XDRIncidentConfiguration controls incident correlation of the alerts.
type XDRIncidentConfiguration struct {
	IsExcludedFromIncidentCorrelation bool `json:"isExcludedFromIncidentCorrelation"`
}
