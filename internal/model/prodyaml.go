package model

// original idea  from here https://github.com/FalconForceTeam/FalconForge/blob/main/usecases/0xFF-0239-Discovery_Commands_Executed_from_Instance_Profile-AWS/usecase.yml
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
	QueryFrequency       string       `yaml:"query_frequency"`
	QueryPeriod          string       `yaml:"query_period"`
}

type Mitre struct {
	Tactics    []string `yaml:"tactics"`
	Techniques []string `yaml:"techniques"`
}

type Entities struct {
	EntityType   string         `yaml:"entity_type"`
	FieldMapping []Fieldmapping `yaml:"field_mapping"`
}

type Fieldmapping struct {
	Identifier string `yaml:"identifier"`
	ColumnName string `yaml:"column_name"`
}

type DataSource struct {
	Provider  string
	EventID   string
	TableName string
}
