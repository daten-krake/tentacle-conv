package model

type DefenderDetectionRule struct {
	DisplayName     string            `json:"displayName"`
	IsEnabled       bool              `json:"isEnabled"`
	QueryCondition  QueryCondition    `json:"queryCondition"`
	Schedule        DetectionSchedule `json:"schedule"`
	DetectionAction DetectionAction   `json:"detectionAction"`
}

type QueryCondition struct {
	QueryText string `json:"queryText"`
}

type DetectionSchedule struct {
	Period string `json:"period"` // "1H", "3H", "12H", "24H", or "0" for NRT
}

type DetectionAction struct {
	AlertTemplate   AlertTemplate    `json:"alertTemplate"`
	ResponseActions []ResponseAction `json:"responseActions"`
}

type AlertTemplate struct {
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	Severity           string          `json:"severity"` // informational, low, medium, high
	Category           string          `json:"category"` // Tactic: Execution, Persistence, etc.
	RecommendedActions string          `json:"recommendedActions"`
	MitreTechniques    []string        `json:"mitreTechniques"`
	ImpactedAssets     []ImpactedAsset `json:"impactedAssets"`
}

type ImpactedAsset struct {
	ODataType  string `json:"@odata.type"`
	Identifier string `json:"identifier"`
}

type ResponseAction struct {
	ODataType string `json:"@odata.type"`
}
