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
	flag.StringVar(&mode, "mode", "", "use for converting  yaml to json default is json to yaml")
	flag.Parse()

	// simple health empty check
	if file == "" {
		log.Fatal("please reference a file")
	}
	if outpath == "" {
		log.Fatal("please add a out path")
	}
	if mode == "" {
		log.Fatal("please select a mode")
	}

	// chek mode
	if mode == "yaml" {
		// check for array conversion or single
		if array {
			test := model.ARMTemplate{}
			conversion.MultiJSONtoYAML(outpath, file, test)
		} else {
			// needs to  be adjusted  for new model
			test := model.Testconv{}
			conversion.SingleJSONtoYAML(outpath, file, test)
		}
	} else if mode == "arm" {
		test := model.Analytic{}
		conversion.SingleYAMLtoARM(outpath, file, test)

	} else if mode == "json" {
		m := model.Analytic{}
		conversion.SingleYAMLtoJSON(outpath, file, m)
	}
}
