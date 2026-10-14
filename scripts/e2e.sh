#!/usr/bin/env bash
# End-to-end conversion test: runs the real tentacle-conv binary over the
# committed rules and checks that rule content survives every conversion.
#
#   ARM (arm/*.json)  -> YAML -> ARM   : round-trip must preserve rule fields
#   YAML (yaml/*.yaml) -> ARM/JSON/Bicep: outputs must be valid and agree
#   Bicep              -> compiled ARM  : must compile and match ARM output
#   testdata/escaping  -> ARM/JSON/Bicep: awkward characters must survive
#
# Requires: jq. Bicep checks need `bicep` or `az bicep` on PATH; set
# REQUIRE_BICEP=1 to fail instead of skipping when neither is available.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${TENTACLE_CONV:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
fail() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
pass() { echo "ok:   $*"; }

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

if [[ -z "$BIN" ]]; then
  BIN="$WORK/tentacle-conv"
  (cd "$ROOT" && go build -o "$BIN" ./cmd/tentacle-conv)
fi

BICEP=()
if command -v bicep >/dev/null; then
  BICEP=(bicep build --stdout)
elif command -v az >/dev/null && az bicep version >/dev/null 2>&1; then
  BICEP=(az bicep build --stdout --file)
elif [[ "${REQUIRE_BICEP:-0}" == 1 ]]; then
  echo "bicep CLI not found and REQUIRE_BICEP=1" >&2
  exit 1
else
  echo "warning: bicep CLI not found, skipping Bicep compilation checks" >&2
fi

# Fields compared across formats; arrays are normalised so null == [].
FIELDS='{
  displayName, description, severity, query, queryFrequency, queryPeriod,
  tactics: (.tactics // []), techniques: (.techniques // []),
  subTechniques: (.subTechniques // []),
  entityMappings: (.entityMappings // [])
}'

# convert <mode> <input> <outdir> -> prints the single produced file
convert() {
  local mode="$1" in="$2" out="$3"
  mkdir -p "$out"
  if ! "$BIN" -mode "$mode" -file "$in" -outpath "$out" 2>"$out.log"; then
    cat "$out.log" >&2
    return 1
  fi
  local files=("$out"/*)
  [[ -f "${files[0]}" && ${#files[@]} -eq 1 ]] || { echo "expected one output in $out" >&2; return 1; }
  echo "${files[0]}"
}

# ── 1. ARM -> YAML -> ARM round-trip ────────────────────────────────────────
shopt -s nullglob
arm_sources=("$ROOT"/arm/*.json "$ROOT"/testdata/testruleset.json)
for arm in "${arm_sources[@]}"; do
  name="$(basename "$arm")"
  ydir="$WORK/rt/$name/yaml"
  mkdir -p "$ydir"
  if ! "$BIN" -mode yaml -array -file "$arm" -outpath "$ydir" 2>"$WORK/rt-$name.log"; then
    cat "$WORK/rt-$name.log" >&2
    fail "$name: ARM -> YAML conversion failed"
    continue
  fi

  want_count="$(jq '.resources | length' "$arm")"
  yamls=("$ydir"/*.yaml)
  if [[ ${#yamls[@]} -ne $want_count ]]; then
    fail "$name: expected $want_count YAML files, got ${#yamls[@]} (duplicate display names?)"
    continue
  fi

  i=0
  for y in "${yamls[@]}"; do
    out="$(convert arm "$y" "$WORK/rt/$name/arm/$i")" || { fail "$name: YAML -> ARM failed for $(basename "$y")"; continue 2; }
    i=$((i + 1))
  done

  # Rule IDs (the last segment of the resource name) must survive too.
  RT='{ id: (.name | sub("^.*/"; "") | sub("\u0027\\)\\]$"; "")), properties: (.properties | '"$FIELDS"') }'
  jq -S "[.resources[] | $RT] | sort_by(.properties.displayName)" "$arm" >"$WORK/rt-$name.want"
  jq -S -s "[.[].resources[] | $RT] | sort_by(.properties.displayName)" "$WORK/rt/$name"/arm/*/*.json >"$WORK/rt-$name.got"
  if diff -u "$WORK/rt-$name.want" "$WORK/rt-$name.got" >"$WORK/rt-$name.diff"; then
    pass "$name: ARM -> YAML -> ARM round-trip ($want_count rules)"
  else
    fail "$name: round-trip changed rule content"
    head -50 "$WORK/rt-$name.diff" >&2
  fi
done

# ── 2. YAML -> ARM / JSON / Bicep ───────────────────────────────────────────
yaml_sources=("$ROOT"/yaml/*.yaml)
[[ ${#yaml_sources[@]} -gt 0 ]] || fail "no YAML rules found in yaml/"

i=0
for y in "${yaml_sources[@]}"; do
  label="$(basename "$y")"
  base="$WORK/yaml/$i"
  i=$((i + 1))

  arm_out="$(convert arm "$y" "$base/arm")" || { fail "$label: YAML -> ARM failed"; continue; }
  json_out="$(convert json "$y" "$base/json")" || { fail "$label: YAML -> JSON failed"; continue; }
  bicep_out="$(convert bicep "$y" "$base/bicep")" || { fail "$label: YAML -> Bicep failed"; continue; }

  jq -S ".resources[0].properties | $FIELDS" "$arm_out" >"$base/arm.fields" \
    || { fail "$label: ARM output is not valid JSON"; continue; }

  if jq -S ".properties | $FIELDS" "$json_out" >"$base/json.fields"; then
    if diff -u "$base/arm.fields" "$base/json.fields" >"$base/json.diff"; then
      pass "$label: JSON output matches ARM"
    else
      fail "$label: JSON output differs from ARM"
      head -30 "$base/json.diff" >&2
    fi
  else
    fail "$label: JSON output is not valid JSON"
  fi

  if [[ ${#BICEP[@]} -gt 0 ]]; then
    if ! "${BICEP[@]}" "$bicep_out" >"$base/bicep.json" 2>"$base/bicep.log"; then
      fail "$label: Bicep compilation failed"
      cat "$base/bicep.log" >&2
      continue
    fi
    jq -S ".resources[0].properties | $FIELDS" "$base/bicep.json" >"$base/bicep.fields"
    if diff -u "$base/arm.fields" "$base/bicep.fields" >"$base/bicep.diff"; then
      pass "$label: Bicep compiles and matches ARM"
    else
      fail "$label: compiled Bicep differs from ARM"
      head -30 "$base/bicep.diff" >&2
    fi
  fi
done

# ── 3. Escaping corpus ──────────────────────────────────────────────────────
# Rules full of quotes, backslashes, "${" and triple quotes must compile to
# exactly the same rule fields as the (JSON-encoded, hence trustworthy) ARM
# output.
escaping_sources=("$ROOT"/testdata/escaping/*.yaml)
i=0
for y in "${escaping_sources[@]}"; do
  label="escaping/$(basename "$y")"
  base="$WORK/escaping/$i"
  i=$((i + 1))

  arm_out="$(convert arm "$y" "$base/arm")" || { fail "$label: YAML -> ARM failed"; continue; }
  json_out="$(convert json "$y" "$base/json")" || { fail "$label: YAML -> JSON failed"; continue; }
  jq -S ".resources[0].properties | $FIELDS" "$arm_out" >"$base/arm.fields"
  jq -S ".properties | $FIELDS" "$json_out" >"$base/json.fields"
  if diff -u "$base/arm.fields" "$base/json.fields" >"$base/json.diff"; then
    pass "$label: JSON output matches ARM"
  else
    fail "$label: JSON output differs from ARM"
    head -30 "$base/json.diff" >&2
  fi

  if [[ ${#BICEP[@]} -gt 0 ]]; then
    bicep_out="$(convert bicep "$y" "$base/bicep")" || { fail "$label: YAML -> Bicep failed"; continue; }
    if ! "${BICEP[@]}" "$bicep_out" >"$base/bicep.json" 2>"$base/bicep.log"; then
      fail "$label: Bicep compilation failed"
      cat "$base/bicep.log" >&2
      continue
    fi
    jq -S ".resources[0].properties | $FIELDS" "$base/bicep.json" >"$base/bicep.fields"
    if diff -u "$base/arm.fields" "$base/bicep.fields" >"$base/bicep.diff"; then
      pass "$label: Bicep compiles and matches ARM"
    else
      fail "$label: compiled Bicep differs from ARM"
      head -30 "$base/bicep.diff" >&2
    fi
  fi
done

echo
if [[ $FAILURES -gt 0 ]]; then
  echo "$FAILURES conversion check(s) failed" >&2
  exit 1
fi
echo "All conversion checks passed"
