package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/daten-krake/tentacle-conv/internal/conversion"
)

// version is set at release time with -ldflags "-X main.version=<tag>".
var version = "dev"

// command is one conversion, available as a subcommand and, for backwards
// compatibility, as a -mode value.
type command struct {
	name  string // subcommand, e.g. "yaml-to-arm"
	mode  string // legacy -mode value, e.g. "arm"
	help  string
	array bool // accepts -array
	run   func(outpath, file string, array bool) error
}

var commands = []command{
	{
		name: "arm-to-yaml", mode: "yaml", array: true,
		help: "convert an ARM template to prodyaml (-array: every rule of a multi-rule template)",
		run: func(outpath, file string, array bool) error {
			if array {
				return conversion.MultiJSONtoYAML(outpath, file)
			}
			return conversion.SingleJSONtoYAML(outpath, file)
		},
	},
	{
		name: "yaml-to-arm", mode: "arm",
		help: "convert a prodyaml rule to an ARM template",
		run: func(outpath, file string, _ bool) error {
			return conversion.SingleYAMLtoARM(outpath, file)
		},
	},
	{
		name: "yaml-to-json", mode: "json",
		help: "convert a prodyaml rule to a Sentinel REST API JSON rule",
		run: func(outpath, file string, _ bool) error {
			return conversion.SingleYAMLtoJSON(outpath, file)
		},
	},
	{
		name: "yaml-to-bicep", mode: "bicep",
		help: "convert a prodyaml rule to a Bicep resource",
		run: func(outpath, file string, _ bool) error {
			return conversion.SingleYAMLtoBicep(outpath, file)
		},
	},
}

func main() {
	log.SetFlags(log.LstdFlags)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	switch args[0] {
	case "-h", "-help", "--help", "help":
		usage(stdout)
		return 0
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "tentacle-conv", version)
		return 0
	}

	if !strings.HasPrefix(args[0], "-") {
		return runSubcommand(args[0], args[1:], stderr)
	}
	return runLegacy(args, stdout, stderr)
}

func findByName(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

func findByMode(mode string) *command {
	for i := range commands {
		if commands[i].mode == mode {
			return &commands[i]
		}
	}
	return nil
}

func runSubcommand(name string, args []string, stderr io.Writer) int {
	cmd := findByName(name)
	if cmd == nil {
		fmt.Fprintf(stderr, "unknown command %q\n\n", name)
		usage(stderr)
		return 2
	}

	fs := flag.NewFlagSet(cmd.name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var file, outpath string
	var array bool
	fs.StringVar(&file, "file", "", "path to the input file")
	fs.StringVar(&outpath, "outpath", "", "directory to write output files (created if missing)")
	if cmd.array {
		fs.BoolVar(&array, "array", false, "write every rule of a multi-rule template to its own file")
	}
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tentacle-conv %s -file <input> -outpath <dir>%s\n\n%s\n\n",
			cmd.name, map[bool]string{true: " [-array]", false: ""}[cmd.array], cmd.help)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	return execute(cmd, outpath, file, array, stderr)
}

// runLegacy handles the original flag-only interface (-mode ...).
func runLegacy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tentacle-conv", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var file, outpath, mode string
	var array bool
	fs.StringVar(&file, "file", "", "path to the input file")
	fs.StringVar(&outpath, "outpath", "", "directory to write output files (created if missing)")
	fs.BoolVar(&array, "array", false, "with -mode yaml: write every rule of a multi-rule ARM template to its own file")
	fs.StringVar(&mode, "mode", "yaml", "conversion mode: yaml, arm, json, bicep")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	cmd := findByMode(mode)
	if cmd == nil {
		fmt.Fprintf(stderr, "unknown mode %q; supported modes: yaml, arm, json, bicep\n", mode)
		return 1
	}
	fmt.Fprintf(stderr, "warning: -mode is deprecated; use 'tentacle-conv %s'\n", cmd.name)
	if array && !cmd.array {
		fmt.Fprintf(stderr, "-array is only supported with -mode yaml, not -mode %s\n", mode)
		return 1
	}
	return execute(cmd, outpath, file, array, stderr)
}

func execute(cmd *command, outpath, file string, array bool, stderr io.Writer) int {
	if file == "" {
		fmt.Fprintln(stderr, "please reference a file with -file")
		return 1
	}
	if outpath == "" {
		fmt.Fprintln(stderr, "please specify an output path with -outpath")
		return 1
	}
	if err := cmd.run(outpath, file, array); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: tentacle-conv <command> -file <input> -outpath <dir> [options]")
	fmt.Fprintln(w, "\nCommands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-14s %s\n", c.name, c.help)
	}
	fmt.Fprintln(w, "  version        print the version")
	fmt.Fprintln(w, "\nRun 'tentacle-conv <command> -h' for the options of a command.")
	fmt.Fprintln(w, "The old form 'tentacle-conv -mode yaml|arm|json|bicep ...' still works but is deprecated.")
}
