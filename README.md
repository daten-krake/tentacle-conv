# tentacle-conv

CLI tool for converting detection rule definitions between YAML, JSON, ARM templates, and Bicep formats for the Tentacle DE Framework.

## Supported Conversions

| Command | Direction | Description |
|---------|-----------|-------------|
| `arm-to-yaml` | ARM → YAML | Converts an ARM template with one rule, or with `-array` every Scheduled rule of a template, into prodyaml |
| `yaml-to-arm` | YAML → ARM | Converts a prodyaml analytic into an Azure Resource Manager (ARM) template JSON |
| `yaml-to-json` | YAML → JSON | Converts a prodyaml analytic into a Sentinel API JSON alert rule |
| `yaml-to-bicep` | YAML → Bicep | Converts a prodyaml analytic into a Bicep alert rule resource |
| `yaml-to-xdr` | YAML → Defender XDR | Converts a prodyaml analytic into a Defender XDR custom detection rule (Microsoft Graph beta `detectionRules` body) |
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

Convert a prodyaml analytic to a Defender XDR custom detection rule and create it:

```bash
tentacle-conv yaml-to-xdr -file rule.yaml -outpath ./xdr/
az rest --method post --url https://graph.microsoft.com/beta/security/rules/detectionRules \
  --body @xdr/<rule name>.json
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

**Defender XDR output.** `yaml-to-xdr` targets the beta Graph API
(`CustomDetection.ReadWrite.All`), uses only the properties that remain after
Microsoft's 2026-10-01 removals, and prints a warning for everything it drops
or approximates:

- `id` is the prodyaml `id`, or a slug of the name; `severity` is lowercased.
- `state: prod` becomes `status: enabled`, any other state `disabled` (with a
  warning). This differs from the other outputs, which always enable the rule.
- `query_period` has no XDR field. For `PT1H`, `PT3H`, `PT12H` and `P1D` the
  lookback is fixed by the service (4 h, 12 h, 48 h, 30 d) and a mismatch is
  reported. Other frequencies between 5 minutes and 14 days are only valid for
  queries on Sentinel data and are reported; anything outside is an error.
  Continuous (NRT) is not produced.
- MITRE: XDR nests techniques under a tactic, but prodyaml's `mitre` entries
  only list tactics and techniques side by side. An entry's techniques are
  attached to every tactic of that entry, and an entry with several tactics and
  techniques produces a warning. Use one `mitre` entry per tactic to pair them
  exactly. Sub-techniques go into `subTechniques`.
- Entity mappings are translated to the typed XDR objects. Identifiers without
  an XDR column (e.g. Process `CommandLine`, File `Directory`, Account
  `ObjectGuid`) and entity types without an equivalent (Malware, FileHash,
  RegistryKey) are reported and skipped. The legacy Account `FullName` becomes
  `upnColumn` when the column name looks like a UPN and `nameColumn` otherwise.
- The query is checked for a missing `ReportId` and for `ago()` filters on
  `Timestamp`/`TimeGenerated`.

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