# tentacle-conv

CLI tool for converting detection rule definitions between YAML, JSON, ARM templates, and Bicep formats for the Tentacle DE Framework.

## Supported Conversions

| Mode | Direction | Description |
|------|-----------|-------------|
| `yaml` | JSON → YAML | Converts a single JSON file to YAML, or an ARM template with multiple resources into separate YAML files |
| `arm` | YAML → ARM | Converts a prodyaml analytic into an Azure Resource Manager (ARM) template JSON |
| `json` | YAML → JSON | Converts a prodyaml analytic into a Sentinel API JSON alert rule |

## Installation

```bash
go install github.com/tentacle-conv/cmd/tentacle-conv@latest
```

Or build from source:

```bash
make build
```

## Usage

```
tentacle-conv -file <input> -outpath <output_dir> -mode <mode> [-array]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-file` | (required) | Path to the input file |
| `-outpath` | (required) | Directory to write output files |
| `-mode` | `yaml` | Conversion mode: `yaml`, `arm`, or `json` |
| `-array` | `false` | Split a multi-resource ARM template into separate YAML files |

### Examples

Convert a prodyaml analytic to an ARM template:

```bash
tentacle-conv -file rule.yaml -outpath ./output/ -mode arm
```

Convert a prodyaml analytic to a Sentinel API JSON rule:

```bash
tentacle-conv -file rule.yaml -outpath ./output/ -mode json
```

Convert a single JSON file to YAML:

```bash
tentacle-conv -file rule.json -outpath ./output/ -mode yaml
```

Convert an ARM template with multiple resources into separate YAML files:

```bash
tentacle-conv -file template.json -outpath ./output/ -mode yaml -array
```

## Development

```bash
make build    # Build all packages
make test     # Run all tests
make vet      # Run go vet
make fmt      # Format code with gofmt
make lint     # Run vet + fmt
make clean    # Remove build artifacts
```

## Project Structure

```
cmd/tentacle-conv/    CLI entry point
internal/
  conversion/         Conversion logic (YAML↔JSON, YAML→ARM, YAML→Bicep)
  model/              Data models for each format
testdata/             Test fixture files
```