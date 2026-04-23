# TODO

## Pending improvements

### Refactor conversion functions to not pass empty model instances

The CLI currently passes empty structs like `model.ARMTemplate{}` just for type dispatch. Consider using generics or separate named functions instead:

```go
// Instead of:
err = conversion.MultiJSONtoYAML(outpath, file, model.ARMTemplate{})

// Option A: Named functions (simplest)
err = conversion.MultiARMToYAML(outpath, file)

// Option B: Generics (more flexible)
err = conversion.JSONToYAML[model.ARMTemplate](outpath, file)
```

Files: `cmd/tentacle-conv/main.go`, `internal/conversion/jsontoyaml.go`

### Add context.Context support to conversion functions

For future-proofing (cancellation, timeouts, tracing), conversion functions should accept `context.Context` as the first parameter, per Go convention:

```go
func SingleYAMLtoJSON(ctx context.Context, outpath string, file string, y model.Analytic) error {
```

Files: `internal/conversion/yamljson.go`, `internal/conversion/yamlbicep.go`, `internal/conversion/yamlarm.go`, `internal/conversion/jsontoyaml.go`

### Improve CLI with subcommands

The current CLI uses raw flags (`-mode yaml`, `-mode arm`). Consider using subcommands for a more idiomatic CLI experience:

```
tentacle-conv yaml-to-json -file input.yaml -outpath ./out/
tentacle-conv yaml-to-arm -file input.yaml -outpath ./out/
tentacle-conv json-to-yaml -file input.json -outpath ./out/
```

This could be done with `flag` subcommands or by adopting `cobra`.

Files: `cmd/tentacle-conv/main.go`

### Add integration tests for I/O round-trip functions

The pure transformation functions (`yamlToJson`, `yamlToArm`, etc.) have good unit test coverage, but the I/O functions (`SingleYAMLtoJSON`, `MultiJSONtoYAML`, etc.) have no tests. Add integration tests that exercise the full file-read → transform → file-write pipeline, using the fixture files in `testdata/`.

Files: New file `internal/conversion/integration_test.go`

### Fix module path in go.mod

The module path `github.com/tentacle-conv` is not a valid Go module path. It should match the actual repository URL (e.g., `github.com/datenkrake/tentacle-conv`). This requires knowing the correct repository owner.

File: `go.mod`