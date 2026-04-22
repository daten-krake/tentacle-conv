package conversion

import (
	"encoding/json"
	"log"
	"os"

	"github.com/tentacle-conv/internal/model"
	"gopkg.in/yaml.v3"
)

func SingleJSONtoYAML(outpath string, file string, test model.Testconv) {
	f, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(f, &test)
	if err != nil {
		log.Fatal(err)
	}
	println("read in: " + file)

	yamlout, err := yaml.Marshal(test)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(outpath+test.Name, yamlout, 0o644)
	if err != nil {
		log.Fatal(err)
	}
}

func MultiJSONtoYAML(outpath string, file string, arm model.ARMTemplate) {
	f, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(f, &arm)
	if err != nil {
		log.Fatal(err)
	}
	println("read in: " + file)

	for i := range arm.Resources {
		yamlout, err := yaml.Marshal(armToAnalytic(arm.Resources[i].Properties))
		if err != nil {
			log.Fatal(err)
		}

		err = os.WriteFile(outpath+arm.Resources[i].Properties.DisplayName+".yaml", yamlout, 0o644)
		if err != nil {
			log.Fatalf("Error writing the file")
		}
	}
}

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

func buildYamlEntityMappings(input []model.ARMEntityMapping) []model.Entities {
	var result []model.Entities

	for _, em := range input {
		entity := model.Entities{
			EntityType: em.EntityType,
		}

		for _, fm := range em.FieldMappings {
			entity.FieldMapping = append(entity.FieldMapping, model.Fieldmapping{
				Identifier: fm.Identifier,
				ColumnName: fm.ColumnName,
			})
		}

		result = append(result, entity)
	}

	return result
}