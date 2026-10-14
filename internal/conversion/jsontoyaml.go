package conversion

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/daten-krake/tentacle-conv/internal/model"
	"gopkg.in/yaml.v3"
)

// ruleIDFromName extracts the rule ID from an ARM resource name expression such
// as [concat(parameters('workspace'),'/Microsoft.SecurityInsights/<id>')].
var ruleIDFromName = regexp.MustCompile(`(?i)(?:^|/)Microsoft\.SecurityInsights/([^'"/\])]+)`)

// armDocument accepts either a full ARM template or a single ARM resource.
type armDocument struct {
	model.ARMResource
	Resources []model.ARMResource `json:"resources"`
}

// SingleJSONtoYAML reads an ARM template (or bare ARM resource) holding exactly
// one Scheduled analytics rule and writes it as prodyaml to outpath. Use
// MultiJSONtoYAML for templates with several rules.
func SingleJSONtoYAML(outpath string, file string) error {
	f, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", file, err)
	}

	var doc armDocument
	if err := json.Unmarshal(f, &doc); err != nil {
		return fmt.Errorf("unmarshaling JSON from %s: %w", file, err)
	}
	log.Println("read in: " + file)

	resources := doc.Resources
	if doc.Resources == nil {
		resources = []model.ARMResource{doc.ARMResource}
	}

	analytics := scheduledRules(resources)
	switch len(analytics) {
	case 0:
		return fmt.Errorf("%s contains no Scheduled analytics rule", file)
	case 1:
	default:
		return fmt.Errorf("%s contains %d analytics rules; use -array to convert all of them", file, len(analytics))
	}

	return writeAnalytic(outpath, analytics[0])
}

// MultiJSONtoYAML reads an ARM template JSON containing multiple resources and
// writes each Scheduled analytics rule as a separate YAML file to outpath.
// Other resources are skipped. Nothing is written if two rules would produce
// the same file name.
func MultiJSONtoYAML(outpath string, file string) error {
	f, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", file, err)
	}

	var arm model.ARMTemplate
	if err := json.Unmarshal(f, &arm); err != nil {
		return fmt.Errorf("unmarshaling JSON from %s: %w", file, err)
	}
	log.Println("read in: " + file)

	analytics := scheduledRules(arm.Resources)
	if len(analytics) == 0 {
		log.Printf("warning: %s contains no Scheduled analytics rules", file)
		return nil
	}

	// Resolve every output path first so a problem leaves no partial output.
	paths := make([]string, len(analytics))
	owner := map[string]string{}
	for i, a := range analytics {
		p, err := outputPath(outpath, a.Name, "yaml")
		if err != nil {
			return fmt.Errorf("resource %d: %w", i, err)
		}
		key := strings.ToLower(p) // case-insensitive filesystems
		if prev, dup := owner[key]; dup {
			return fmt.Errorf("rules %q and %q both map to %s", prev, a.Name, p)
		}
		owner[key] = a.Name
		paths[i] = p
	}

	for i, a := range analytics {
		yamlout, err := yaml.Marshal(a)
		if err != nil {
			return fmt.Errorf("marshaling YAML for rule %q: %w", a.Name, err)
		}
		if err := writeFile(outpath, paths[i], yamlout); err != nil {
			return err
		}
	}
	return nil
}

func writeAnalytic(outpath string, a model.Analytic) error {
	yamlout, err := yaml.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshaling YAML: %w", err)
	}
	return writeOutput(outpath, a.Name, "yaml", yamlout)
}

// scheduledRules converts the Scheduled analytics rules among resources,
// logging a warning for every resource that is skipped.
func scheduledRules(resources []model.ARMResource) []model.Analytic {
	var out []model.Analytic
	for i, r := range resources {
		if reason := notScheduledRule(r); reason != "" {
			log.Printf("warning: skipping resource %d (%s): %s", i, resourceLabel(r), reason)
			continue
		}
		out = append(out, armToAnalytic(r))
	}
	return out
}

// notScheduledRule returns why r is not a Scheduled analytics rule, or "" if
// it is one.
func notScheduledRule(r model.ARMResource) string {
	if !strings.HasSuffix(strings.ToLower(r.Type), "/alertrules") {
		return fmt.Sprintf("type %q is not an analytics rule", r.Type)
	}
	if !strings.EqualFold(r.Kind, ruleKind) {
		return fmt.Sprintf("kind %q is not supported, only %s rules are converted", r.Kind, ruleKind)
	}
	return ""
}

func resourceLabel(r model.ARMResource) string {
	if r.Properties.DisplayName != "" {
		return r.Properties.DisplayName
	}
	return r.Name
}

// armToAnalytic converts an ARM resource into a prodyaml Analytic model.
//
// prodyaml has no fields for enabled, trigger operator/threshold, suppression,
// incident configuration or event grouping, so those ARM settings are not
// carried over; the YAML -> ARM direction applies fixed defaults for them.
func armToAnalytic(r model.ARMResource) model.Analytic {
	p := r.Properties
	return model.Analytic{
		ID:             ruleIDOf(r),
		Name:           p.DisplayName,
		Severity:       p.Severity,
		Description:    p.Description,
		Query:          p.Query,
		QueryFrequency: p.QueryFrequency,
		QueryPeriod:    p.QueryPeriod,
		Mitre: []model.Mitre{
			{
				Tactics:    p.Tactics,
				Techniques: mergeTechniques(p.Techniques, p.SubTechniques),
			},
		},
		EntityMapping: buildYamlEntityMappings(p.EntityMappings),
	}
}

// ruleIDOf returns the rule ID (the last segment of the resource name), or ""
// when the name is not a literal this converter can read, e.g. a variable.
func ruleIDOf(r model.ARMResource) string {
	name := strings.TrimSpace(r.Name)
	if model.ValidRuleID(name) {
		return name
	}
	if m := ruleIDFromName.FindStringSubmatch(name); m != nil && model.ValidRuleID(m[1]) {
		return m[1]
	}
	if name != "" {
		log.Printf("warning: cannot read a rule ID from resource name %q; id is left empty", name)
	}
	return ""
}

// buildYamlEntityMappings converts a slice of ARM entity mappings to the
// prodyaml entity format.
func buildYamlEntityMappings(input []model.ARMEntityMapping) []model.Entities {
	var result []model.Entities

	for _, em := range input {
		entity := model.Entities{
			EntityType: em.EntityType,
		}

		for _, fm := range em.FieldMappings {
			entity.FieldMapping = append(entity.FieldMapping, model.FieldMapping{
				Identifier: fm.Identifier,
				ColumnName: fm.ColumnName,
			})
		}

		result = append(result, entity)
	}

	return result
}
