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
)

func main() {
	// TODO clean up usage and help
	flag.StringVar(&file, "file", "", "testing: a path to file")
	flag.StringVar(&outpath, "outpath", "", "testing: add a out path")
	flag.BoolVar(&array, "array", false, "temporary solution, use if you want to convert an array into multiple yaml")
	flag.Parse()

	// simple health empty check
	if file == "" {
		log.Fatal("please reference a file")
	}
	if outpath == "" {
		log.Fatal("please add a out path")
	}
	// check for array conversion or single
	if array {
		test := []model.Testconv{}
		conversion.MultiJSONtoYAML(outpath, file, test)
	} else {
		test := model.Testconv{}
		conversion.SingleJSONtoYAML(outpath, file, test)
	}
}
