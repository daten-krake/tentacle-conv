package model

// Analytic represents a detection rule in the prodyaml format, which serves as
// the canonical internal representation for conversion to other formats.
// Based on https://github.com/FalconForceTeam/FalconForge/blob/main/usecases/0xFF-0239-Discovery_Commands_Executed_from_Instance_Profile-AWS/usecase.yml
type Analytic struct {
	ID                   string       `yaml:"id"`
	Name                 string       `yaml:"name"`
	Severity             string       `yaml:"severity"`
	FPRate               string       `yaml:"fp_rate"`
	PermissionRequired   string       `yaml:"permission_required"`
	Mitre                []Mitre      `yaml:"mitre"`
	EntityMapping        []Entities   `yaml:"entity_mapping"`
	DataSources          []DataSource `yaml:"data_sources"`
	Tags                 []string     `yaml:"tags"`
	OSFamily             []string     `yaml:"os_family"`
	Description          string       `yaml:"description"`
	TechnicalDescription string       `yaml:"technical_description"`
	Considerations       string       `yaml:"considerations"`
	FalsePositives       string       `yaml:"false_positives"`
	Blindspots           string       `yaml:"blindspots"`
	ResponsePlan         string       `yaml:"response_plan"`
	References           []string     `yaml:"references"`
	Query                string       `yaml:"query"`
	TestBlock            string       `yaml:"test_block"`
	QueryFrequency       string       `yaml:"query_frequency"`
	QueryPeriod          string       `yaml:"query_period"`
}

// Mitre holds MITRE ATT&CK tactics and techniques for a detection rule.
type Mitre struct {
	Tactics    []string `yaml:"tactics"`
	Techniques []string `yaml:"techniques"`
}

// Entities maps an entity type to its field mappings in prodyaml format.
type Entities struct {
	EntityType  string         `yaml:"entity_type"`
	FieldMapping []FieldMapping `yaml:"field_mapping"`
}

// FieldMapping maps an identifier to a column name in prodyaml format.
type FieldMapping struct {
	Identifier string `yaml:"identifier"`
	ColumnName string `yaml:"column_name"`
}

// DataSource describes the data source for a detection rule.
type DataSource struct {
	Provider  string `yaml:"provider" json:"provider"`
	EventID   string `yaml:"event_id" json:"event_id"`
	TableName string `yaml:"table_name" json:"table_name"`
}