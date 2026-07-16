// Command eventheader-gen generates typed EventHeader writers from annotated structs.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cataggar/LinuxTracepoints-Go/cmd/eventheader-gen/internal/generator"
)

const version = "eventheader-gen 1.0.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("eventheader-gen", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var typeNames, output, tags string
	var check, showVersion bool
	flags.StringVar(&typeNames, "type", "", "comma-separated event struct type names")
	flags.StringVar(&output, "output", "", "output file name")
	flags.StringVar(&tags, "tags", "", "comma-separated build tags")
	flags.BoolVar(&check, "check", false, "verify generated output is current without writing")
	flags.BoolVar(&showVersion, "version", false, "print version")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "eventheader-gen: positional arguments are not accepted")
		return 2
	}
	if showVersion {
		if typeNames != "" || output != "" || tags != "" || check {
			fmt.Fprintln(os.Stderr, "eventheader-gen: -version cannot be combined with generation flags")
			return 2
		}
		fmt.Fprintln(os.Stdout, version)
		return 0
	}
	if check && output == "-" {
		fmt.Fprintln(os.Stderr, "eventheader-gen: -check cannot be used with -output=-")
		return 2
	}
	var types []string
	if typeNames != "" {
		types = strings.Split(typeNames, ",")
		seen := make(map[string]bool)
		for _, name := range types {
			if name == "" || seen[name] {
				fmt.Fprintln(os.Stderr, "eventheader-gen: -type must contain unique nonempty names")
				return 2
			}
			seen[name] = true
		}
	}
	err := generator.Write(generator.Config{
		Types: types, Output: output, Tags: tags, Check: check, Dir: ".",
	})
	if err != nil {
		var diagnostic *generator.Diagnostic
		if errors.As(err, &diagnostic) {
			fmt.Fprintln(os.Stderr, err)
		} else {
			fmt.Fprintf(os.Stderr, "eventheader-gen: %v\n", err)
		}
		return 1
	}
	return 0
}
