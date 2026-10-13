# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tentacle-conv` is a Go CLI that converts Microsoft Sentinel detection rules between the "prodyaml" format (the canonical, human-edited YAML) and deployable formats: ARM template JSON, Sentinel REST API JSON, and Bicep. It also converts exported ARM templates back into prodyaml.

## Commands

```bash
make build                     # go build ./...
make test                      # go test ./... -v -count=1  (also: scripts/test.sh [go test args])
make vet / make fmt / make lint
go test ./internal/conversion -run TestGenerateBicepDSL -v   # single test
UPDATE_GOLDEN=1 go test ./internal/conversion -run TestGenerateBicepDSL  # regenerate Bicep golden file
go build -o tentacle-conv ./cmd/tentacle-conv               # binary used by the sync script
bash scripts/e2e.sh            # end-to-end conversion checks (needs jq; bicep CLI optional, REQUIRE_BICEP=1 to enforce)
./tentacle-conv -mode <yaml|arm|json|bicep> [-array] -file <in> -outpath <existing dir>
```

## Architecture

- `internal/model/` holds one struct set per format. `prodyaml.go` (`Analytic`) is the source of truth for rule content. `armtemplate.go` (ARM) and `sentinelapi.go` (REST API) are output shapes. `common.go` holds incident/grouping types shared by both.
- `internal/conversion/` has one file per direction. Each `Single*`/`Multi*` function reads the file, unmarshals it, calls a pure mapping function (`yamlToArm`, `yamlToJson`, `generateBicepDSL`, `armToAnalytic`), and writes `<rule name>.<ext>` into `-outpath`. Unit tests target the pure mappers; the I/O wrappers are untested.
  - Rule settings that prodyaml doesn't model (trigger operator/threshold, suppression, incident grouping, `enabled: true`, API version `2023-12-01-preview`) are **hard-coded** separately in `yamlarm.go`, `yamljson.go` and the Bicep template string in `yamlbicep.go`. When changing a default, update all three.
  - Bicep is generated from a `text/template` with custom escape funcs. Its golden file is `testdata/out/TestGenerateBicepDSL.bicep`.
  - `mitre.go` flattens the `mitre:` list into tactics/techniques arrays.
- `cmd/tentacle-conv/main.go` is flag parsing plus dispatch on `-mode`. Conversion functions take an empty model value only for typing (#29).

### ARM → YAML pipeline (repo as rule store)

- `arm/` holds exported ARM templates. `yaml/` holds generated prodyaml. Both are committed.
- `.github/workflows/arm-to-yaml.yml` runs on pushes touching `arm/**`: it builds the binary and runs `scripts/sync_arm_to_yaml.py`, then commits the results with `[skip ci]`.
- The sync script keeps an `arm/<file>.json.manifest` per ARM file, holding the source SHA-256 and the YAML files generated from it. It skips conversion when the hash is unchanged, so converter changes don't regenerate existing YAML. It never deletes YAML; unreferenced files only produce orphan warnings.
- `scripts/deploy_bicep.sh` builds a parent Bicep from one or more generated `.bicep` files (one module each) and deploys them with `az deployment group`. It needs bash ≥ 4 and GNU grep/realpath, so it won't run with the macOS defaults.

### CI

`.github/workflows/ci.yml` runs on every PR and on pushes to `main`. It has two jobs, **Unit tests** (build, vet, `go test -race`) and **Conversion e2e** (`scripts/e2e.sh`). The e2e script runs the real binary over `arm/*.json`, `testdata/testruleset.json` and `yaml/*.yaml`. It checks the ARM → YAML → ARM round-trip, that JSON output matches ARM output, and that generated Bicep compiles (pinned Bicep CLI) to the same rule fields as the ARM output. A change to any converter must keep these outputs in agreement.

### Release

Pushing a `v*` tag runs `.github/workflows/release.yml`, which cross-compiles the binary for linux/darwin/windows and creates a GitHub release with checksums.

## Notes

- The module path is `github.com/tentacle-conv` (not the real repo path `github.com/daten-krake/tentacle-conv`); imports must use the module path.
- Known bugs, edge cases and planned work are tracked as GitHub issues (e.g. Bicep escaping of non-query fields, unsanitized output filenames, JSON-mode defaults, deploy script portability, new OpenTofu/Defender XDR outputs). Check `gh issue list` before touching the related code. There is no TODO file.
