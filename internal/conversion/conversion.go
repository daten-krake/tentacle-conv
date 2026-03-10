package conversion

import (
	"encoding/json"
	"fmt"
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
	fmt.Println("read in: " + file)

	yamlout, err := yaml.Marshal(test)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(outpath+test.Name, yamlout, 0o644)
	if err != nil {
		log.Fatal(err)
	}
}

func MultiJSONtoYAML(outpath string, file string, test []model.Testconv) {
	f, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(f, &test)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("read in: " + file)

	for i := range test {

		yamlout, err := yaml.Marshal(test[i])
		if err != nil {
			log.Fatal(err)
		}

		err = os.WriteFile(outpath+test[i].Name, yamlout, 0o644)
		if err != nil {
			log.Fatal(err)
		}

	}
}
