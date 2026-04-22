package conversion

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/tentacle-conv/internal/model"
	"gopkg.in/yaml.v3"
)

// SingleJSONtoYAML reads a single JSON file and writes the corresponding YAML
// representation to outpath.
func SingleJSONtoYAML(outpath string, file string) error {
	f, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", file, err)
	}

	var data map[string]any
	err = json.Unmarshal(f, &data)
	if err != nil {
		return fmt.Errorf("unmarshaling JSON from %s: %w", file, err)
	}
	log.Println("read in: " + file)

	yamlout, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling YAML: %w", err)
	}

	name, _ := data["name"].(string)
	if name == "" {
		name = filepath.Base(file)
	}

	outFile := filepath.Join(outpath, name+".yaml")
	err = os.WriteFile(outFile, yamlout, 0o644)
	if err != nil {
		return fmt.Errorf("writing file %s: %w", outFile, err)
	}
	return nil
}

// MultiJSONtoYAML reads an ARM template JSON containing multiple resources and
// writes each as a separate YAML file to outpath.
func MultiJSONtoYAML(outpath string, file string, arm model.ARMTemplate) error {
	f, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", file, err)
	}

	err = json.Unmarshal(f, &arm)
	if err != nil {
		return fmt.Errorf("unmarshaling JSON from %s: %w", file, err)
	}
	log.Println("read in: " + file)

	for i := range arm.Resources {
		yamlout, err := yaml.Marshal(armToAnalytic(arm.Resources[i].Properties))
		if err != nil {
			return fmt.Errorf("marshaling YAML for resource %d: %w", i, err)
		}

		outFile := filepath.Join(outpath, arm.Resources[i].Properties.DisplayName+".yaml")
		err = os.WriteFile(outFile, yamlout, 0o644)
		if err != nil {
			return fmt.Errorf("writing file %s: %w", outFile, err)
		}
	}
	return nil
}

// armToAnalytic converts ARM template properties into a prodyaml Analytic model.
func armToAnalytic(arm model.ARMProperties) model.Analytic {
	return model.Analytic{
		Name:           arm.DisplayName,
		Severity:       arm.Severity,
		Description:    arm.Description,
		Query:          arm.Query,
		QueryFrequency: arm.QueryFrequency,
		QueryPeriod:    arm.QueryPeriod,
		Mitre: []model.Mitre{
			{
				Tactics:    arm.Tactics,
				Techniques: arm.Techniques,
			},
		},
		EntityMapping: buildYamlEntityMappings(arm.EntityMappings),
	}
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