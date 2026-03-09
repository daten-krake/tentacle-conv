package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type testconv struct {
	Name string `json:"name" yaml:"name"`
	Test string `json:"test" yaml:"test"`
}

var (
	outpath string
	file    string
)

func main() {
	flag.StringVar(&file, "file", "", "testing: a path to file")
	flag.StringVar(&outpath, "outpath", "", "testing: add a out path")
	flag.Parse()

	if file == "" {
		log.Fatal("please reference a file")
	}
	if outpath == "" {
		log.Fatal("please add a out path")
	}
	test := testconv{}
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

	err = os.WriteFile(outpath, yamlout, 0o644)
	if err != nil {
		log.Fatal(err)
	}
}
