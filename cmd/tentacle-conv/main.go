package main

import (
	"flag"
	"fmt"
	"log"
	"os"

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
	flag.StringVar(&file, "file", "", "path to the input file")
	flag.StringVar(&outpath, "outpath", "", "directory to write output files")
	flag.BoolVar(&array, "array", false, "convert a JSON array into multiple YAML files")
	flag.StringVar(&mode, "mode", "yaml", "conversion mode: yaml, arm, or json")
	flag.Parse()

	if file == "" {
		log.Fatal("please reference a file with -file")
	}
	if outpath == "" {
		log.Fatal("please specify an output path with -outpath")
	}

	var err error
	switch mode {
	case "yaml":
		if array {
			err = conversion.MultiJSONtoYAML(outpath, file, model.ARMTemplate{})
		} else {
			err = conversion.SingleJSONtoYAML(outpath, file)
		}
	case "arm":
		err = conversion.SingleYAMLtoARM(outpath, file, model.Analytic{})
	case "json":
		err = conversion.SingleYAMLtoJSON(outpath, file, model.Analytic{})
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q; supported modes: yaml, arm, json\n", mode)
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
}