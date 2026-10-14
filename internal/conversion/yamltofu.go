package conversion

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/daten-krake/tentacle-conv/internal/model"
)

// Limits of azurerm_sentinel_alert_rule_scheduled (checked against azurerm
// 5.9.0 with `terraform providers schema`).
const (
	tofuMaxEntityMappings = 10
	tofuMaxFieldMappings  = 3
)

// tofuVersionsFile and tofuVariablesFile are written next to the rule files
// when missing, so the output directory validates as it is. Every rule file
// refers to var.workspace_id, which must be declared exactly once.
const (
	tofuVersionsFile  = "versions.tf"
	tofuVariablesFile = "variables.tf"
)

const tofuVersionsContent = `terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
  }
}
`

const tofuVariablesContent = `variable "workspace_id" {
  description = "Resource ID of the Log Analytics workspace that has Microsoft Sentinel enabled."
  type        = string
}
`

// SingleYAMLtoTofu reads a YAML analytic file, converts it to an OpenTofu/
// Terraform configuration holding one azurerm_sentinel_alert_rule_scheduled
// resource, and writes <rule name>.tf to outpath. versions.tf and
// variables.tf are created there if they do not exist yet.
func SingleYAMLtoTofu(outpath string, file string) error {
	y, err := loadAnalytic(file)
	if err != nil {
		return err
	}

	hcl, err := generateTofuHCL(y)
	if err != nil {
		return fmt.Errorf("generating OpenTofu configuration for %s: %w", file, err)
	}

	if err := writeOutput(outpath, y.Name, "tf", []byte(hcl)); err != nil {
		return err
	}
	for name, content := range map[string]string{
		tofuVersionsFile:  tofuVersionsContent,
		tofuVariablesFile: tofuVariablesContent,
	} {
		path := filepath.Join(outpath, name)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := writeFile(outpath, path, []byte(content)); err != nil {
			return err
		}
	}
	return nil
}

var nonLabelChars = regexp.MustCompile(`[^a-z0-9_]+`)

// tofuResourceLabel derives the resource label (the address inside the state)
// from the rule id, or from the name when there is no id. The label never
// starts with a digit and only contains [a-z0-9_].
func tofuResourceLabel(a model.Analytic) string {
	src := a.ID
	if src == "" {
		src = a.Name
	}
	label := nonLabelChars.ReplaceAllString(strings.ToLower(src), "_")
	label = strings.Trim(label, "_")
	if label == "" || (label[0] >= '0' && label[0] <= '9') {
		label = "rule_" + label
	}
	return strings.TrimRight(label, "_")
}

// hclQuote renders s as a double-quoted HCL string literal. It escapes the
// characters HCL treats specially: \ and ", the template sequences ${ and %{
// (as $${ and %%{) and control characters.
func hclQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	rs := []rune(s)
	for i, r := range rs {
		next := rune(0)
		if i+1 < len(rs) {
			next = rs[i+1]
		}
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case (r == '$' || r == '%') && next == '{':
			// "${" -> "$${", "%{" -> "%%{": double the introducer.
			b.WriteRune(r)
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// hclQuery renders a KQL query as an HCL expression whose value is exactly
// the query. Multi-line queries become a heredoc, which keeps them readable;
// a delimiter that does not occur as a line of the query is chosen. Anything
// a heredoc cannot carry unchanged falls back to a quoted string.
func hclQuery(q string) string {
	if !strings.Contains(q, "\n") || strings.ContainsAny(q, "\r\x00") || strings.HasPrefix(q, "\n") {
		return hclQuote(q)
	}

	delim := "KQL"
	lines := map[string]bool{}
	for _, l := range strings.Split(q, "\n") {
		lines[strings.TrimSpace(l)] = true
	}
	for i := 1; lines[delim]; i++ {
		delim = fmt.Sprintf("KQL_%d", i)
	}

	// Heredoc content may not contain template sequences; escape them.
	body := strings.NewReplacer("${", "$${", "%{", "%%{").Replace(q)

	// A heredoc value always ends with a newline. Keep the query's own
	// trailing newline, or strip the one the heredoc adds.
	if strings.HasSuffix(q, "\n") {
		return "<<" + delim + "\n" + body + delim
	}
	// The closing parenthesis is indented the way `tofu fmt` writes it for a
	// top-level argument.
	return "chomp(<<" + delim + "\n" + body + "\n" + delim + "\n  )"
}

// hclList renders a list of strings as an HCL list expression.
func hclList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = hclQuote(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

type tofuAttr struct{ key, val string }

// writeAttrs writes attributes with the '=' signs aligned the way
// `tofu fmt` does.
func writeAttrs(b *strings.Builder, indent string, attrs []tofuAttr) {
	width := 0
	for _, a := range attrs {
		if len(a.key) > width {
			width = len(a.key)
		}
	}
	for _, a := range attrs {
		fmt.Fprintf(b, "%s%-*s = %s\n", indent, width, a.key, a.val)
	}
}

// generateTofuHCL maps a prodyaml Analytic to an azurerm Sentinel scheduled
// alert rule. It uses the same fixed settings as the other outputs.
func generateTofuHCL(a model.Analytic) (string, error) {
	p := ruleProperties(a)

	if n := len(p.EntityMappings); n > tofuMaxEntityMappings {
		return "", fmt.Errorf("%d entity mappings; azurerm allows at most %d", n, tofuMaxEntityMappings)
	}
	for _, em := range p.EntityMappings {
		if n := len(em.FieldMappings); n > tofuMaxFieldMappings {
			return "", fmt.Errorf("entity %q has %d field mappings; azurerm allows at most %d", em.EntityType, n, tofuMaxFieldMappings)
		}
		if len(em.FieldMappings) == 0 {
			return "", fmt.Errorf("entity %q has no field mappings; azurerm requires at least one", em.EntityType)
		}
	}

	var b strings.Builder
	if len(p.SubTechniques) > 0 {
		fmt.Fprintf(&b, "# azurerm_sentinel_alert_rule_scheduled has no sub-technique argument; not applied: %s\n",
			strings.NewReplacer("\n", " ", "\r", " ").Replace(strings.Join(p.SubTechniques, ", ")))
	}
	fmt.Fprintf(&b, "resource \"azurerm_sentinel_alert_rule_scheduled\" %s {\n", hclQuote(tofuResourceLabel(a)))

	head := []tofuAttr{
		{"name", hclQuote(ruleID(a))},
		{"log_analytics_workspace_id", "var.workspace_id"},
		{"display_name", hclQuote(p.DisplayName)},
		{"description", hclQuote(p.Description)},
		{"severity", hclQuote(p.Severity)},
		{"enabled", fmt.Sprint(p.Enabled)},
	}
	tail := []tofuAttr{
		{"query_frequency", hclQuote(p.QueryFrequency)},
		{"query_period", hclQuote(p.QueryPeriod)},
		{"trigger_operator", hclQuote(p.TriggerOperator)},
		{"trigger_threshold", fmt.Sprint(p.TriggerThreshold)},
		{"suppression_enabled", fmt.Sprint(p.SuppressionEnabled)},
		{"suppression_duration", hclQuote(p.SuppressionDuration)},
		{"tactics", hclList(p.Tactics)},
		{"techniques", hclList(p.Techniques)},
	}

	// `tofu fmt` aligns '=' within a run of arguments. A bare heredoc stays in
	// the run, but the multi-line chomp(...) call ends it.
	query := tofuAttr{"query", hclQuery(p.Query)}
	if strings.HasPrefix(query.val, "chomp(") {
		writeAttrs(&b, "  ", head)
		writeAttrs(&b, "  ", []tofuAttr{query})
		writeAttrs(&b, "  ", tail)
	} else {
		writeAttrs(&b, "  ", append(append(head, query), tail...))
	}

	for _, em := range p.EntityMappings {
		b.WriteString("\n  entity_mapping {\n")
		writeAttrs(&b, "    ", []tofuAttr{{"entity_type", hclQuote(em.EntityType)}})
		for _, fm := range em.FieldMappings {
			b.WriteString("\n    field_mapping {\n")
			writeAttrs(&b, "      ", []tofuAttr{
				{"identifier", hclQuote(fm.Identifier)},
				{"column_name", hclQuote(fm.ColumnName)},
			})
			b.WriteString("    }\n")
		}
		b.WriteString("  }\n")
	}

	ic := p.IncidentConfiguration
	g := ic.GroupingConfiguration
	b.WriteString("\n  incident {\n")
	writeAttrs(&b, "    ", []tofuAttr{{"create_incident_enabled", fmt.Sprint(ic.CreateIncident)}})
	b.WriteString("\n    grouping {\n")
	writeAttrs(&b, "      ", []tofuAttr{
		{"enabled", fmt.Sprint(g.Enabled)},
		{"lookback_duration", hclQuote(g.LookbackDuration)},
		{"entity_matching_method", hclQuote(g.MatchingMethod)},
	})
	b.WriteString("    }\n  }\n")

	b.WriteString("\n  event_grouping {\n")
	writeAttrs(&b, "    ", []tofuAttr{{"aggregation_method", hclQuote(p.EventGroupingSettings.AggregationKind)}})
	b.WriteString("  }\n}\n")

	return b.String(), nil
}
