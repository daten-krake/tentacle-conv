# tentacle-conv

CLI tool for converting detection rule definitions between YAML, JSON, ARM templates, and Bicep formats for the Tentacle DE Framework.

## Supported Conversions

| Command | Direction | Description |
|---------|-----------|-------------|
| `arm-to-yaml` | ARM → YAML | Converts an ARM template with one rule, or with `-array` every Scheduled rule of a template, into prodyaml |
| `yaml-to-arm` | YAML → ARM | Converts a prodyaml analytic into an Azure Resource Manager (ARM) template JSON |
| `yaml-to-json` | YAML → JSON | Converts a prodyaml analytic into a Sentinel API JSON alert rule |
| `yaml-to-bicep` | YAML → Bicep | Converts a prodyaml analytic into a Bicep alert rule resource |
| `yaml-to-tofu` | YAML → OpenTofu | Converts a prodyaml analytic into an OpenTofu/Terraform `azurerm_sentinel_alert_rule_scheduled` resource |

## Installation

```bash
go install github.com/daten-krake/tentacle-conv/cmd/tentacle-conv@latest
```

Or build from source:

```bash
make build
```

## Usage

```
tentacle-conv <command> -file <input> -outpath <output_dir> [-array]
tentacle-conv version
```

The earlier form `tentacle-conv -mode yaml|arm|json|bicep ...` still works but
is deprecated and prints a warning.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-file` | (required) | Path to the input file |
| `-outpath` | (required) | Directory to write output files; created if it does not exist |
| `-array` | `false` | `arm-to-yaml` only: write every Scheduled rule of a multi-rule ARM template to its own YAML file |

### Examples

Convert a prodyaml analytic to an ARM template:

```bash
tentacle-conv yaml-to-arm -file rule.yaml -outpath ./output/
```

Convert a prodyaml analytic to a Sentinel API JSON rule:

```bash
tentacle-conv yaml-to-json -file rule.yaml -outpath ./output/
```

Convert a prodyaml analytic to a Bicep resource:

```bash
tentacle-conv yaml-to-bicep -file rule.yaml -outpath ./output/
```

Convert a prodyaml analytic to an OpenTofu/Terraform configuration:

```bash
tentacle-conv yaml-to-tofu -file rule.yaml -outpath ./tf/
tofu -chdir=tf init && tofu -chdir=tf plan -var workspace_id=<workspace resource id>
```

Convert an ARM template that holds one rule to YAML:

```bash
tentacle-conv arm-to-yaml -file rule.json -outpath ./output/
```

Convert an ARM template with multiple resources into separate YAML files:

```bash
tentacle-conv arm-to-yaml -file template.json -outpath ./output/ -array
```

## Behaviour worth knowing

**Input validation.** prodyaml files are decoded strictly: unknown keys (for
example a typo such as `query_freqency`) are an error. `name`, `query`,
`severity` (`Informational`, `Low`, `Medium`, `High`), `query_frequency` and
`query_period` (ISO 8601 durations such as `PT1H`, `P1D`) are required.

**Rule IDs.** The ARM/Bicep resource name is the rule's `id`. If `id` is empty
a stable GUID is derived from the rule name, so renaming a rule's display name
does not create a second rule. `id` may only contain letters, digits, `.`, `_`
and `-`. When converting ARM → YAML the ID is read from the resource name.

**Output file names.** Files are named after the rule name. Path separators and
characters reserved on common filesystems become `_`. With `-array`, two rules
that would produce the same file name are an error and nothing is written.

**MITRE sub-techniques.** `T1059.001` in prodyaml is written as the parent
`T1059` in `techniques` and the full ID in `subTechniques`. ARM → YAML merges
both back into the prodyaml `techniques` list.

**ARM → YAML only converts `Scheduled` rules.** Other kinds (NRT, Fusion, ...)
and non-rule resources are skipped with a warning.

**Settings prodyaml does not model are not round-tripped.** ARM → YAML drops
`enabled`, `triggerOperator`, `triggerThreshold`, `suppressionEnabled`,
`suppressionDuration`, `incidentConfiguration` and `eventGroupingSettings`.
YAML → ARM/JSON/Bicep always writes the same fixed defaults for them
(`enabled: true`, `GreaterThan`/`0`, suppression off with `PT5H`, incident
creation on with grouping `AllEntities` over `P7D`, `AlertPerResult`). These
defaults live in `internal/conversion/rule.go`.

**OpenTofu output.** `yaml-to-tofu` writes `<rule name>.tf` with one
`azurerm_sentinel_alert_rule_scheduled`, and creates `versions.tf` and
`variables.tf` (declaring `workspace_id`) in the output directory if they do not
exist yet; existing files are never overwritten. The resource `name` is the rule
id (see *Rule IDs*), and the resource label is derived from the id, or from the
name when there is none, so renaming a rule's display name updates it in place.
The azurerm resource has no sub-technique argument, so sub-techniques are only
listed in a comment. The generated configuration was validated against azurerm
5.9.0. azurerm allows at most 10 entity mappings with at most 3 field mappings
each; more is an error.

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