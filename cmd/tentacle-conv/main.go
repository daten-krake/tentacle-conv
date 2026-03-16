package main

import (
	"flag"
	"log"

	"github.com/tentacle-conv/internal/conversion"
	"github.com/tentacle-conv/internal/model"
)

var (
	outpath string
	file    string
	array   bool
	mode    string
)

func main() {
	// TODO clean up usage and help
	flag.StringVar(&file, "file", "", "testing: a path to file")
	flag.StringVar(&outpath, "outpath", "", "testing: add a out path")
	flag.BoolVar(&array, "array", false, "temporary solution, use if you want to convert an array into multiple yaml")
	flag.StringVar(&mode, "mode", "yaml", "use for converting  yaml to json default is json to yaml")
	flag.Parse()

	// simple health empty check
	if file == "" {
		log.Fatal("please reference a file")
	}
	if outpath == "" {
		log.Fatal("please add a out path")
	}

	// chek mode
	if mode == "yaml" {
		// check for array conversion or single
		if array {
			test := model.ARMTemplate{}
			conversion.MultiJSONtoYAML(outpath, file, test)
		} else {
			test := model.Testconv{}
			conversion.SingleJSONtoYAML(outpath, file, test)
		}
	} else {
		test := model.Analytic{}
		conversion.SingleYAMLtoJSON(outpath, file, test)

	}
}
