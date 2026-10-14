package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/daten-krake/tentacle-conv/internal/conversion"
)

// version is set at release time with -ldflags "-X main.version=<tag>".
var version = "dev"

var (
	outpath     string
	file        string
	array       bool
	mode        string
	showVersion bool
)

func main() {
	flag.StringVar(&file, "file", "", "path to the input file")
	flag.StringVar(&outpath, "outpath", "", "directory to write output files (created if missing)")
	flag.BoolVar(&array, "array", false, "with -mode yaml: convert every rule of an ARM template into its own YAML file")
	flag.StringVar(&mode, "mode", "yaml", "conversion mode: yaml, arm, json, bicep")
	flag.BoolVar(&showVersion, "version", false, "print the version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("tentacle-conv", version)
		return
	}

	if file == "" {
		log.Fatal("please reference a file with -file")
	}
	if outpath == "" {
		log.Fatal("please specify an output path with -outpath")
	}
	if array && mode != "yaml" {
		log.Fatalf("-array is only supported with -mode yaml, not -mode %s", mode)
	}

	var err error
	switch mode {
	case "yaml":
		if array {
			err = conversion.MultiJSONtoYAML(outpath, file)
		} else {
			err = conversion.SingleJSONtoYAML(outpath, file)
		}
	case "arm":
		err = conversion.SingleYAMLtoARM(outpath, file)
	case "json":
		err = conversion.SingleYAMLtoJSON(outpath, file)
	case "bicep":
		err = conversion.SingleYAMLtoBicep(outpath, file)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q; supported modes: yaml, arm, json, bicep\n", mode)
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
}
