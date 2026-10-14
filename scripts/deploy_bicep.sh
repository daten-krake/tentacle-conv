#!/usr/bin/env bash
# Interactive Bicep deployment script for Sentinel alert rules
# Deploys one or more .bicep files to a resource group in a single deployment.
#
# Portable: works with bash 3.2 (macOS default) and BSD or GNU userland. The
# only external tool required is the Azure CLI.
set -euo pipefail

# ──────────────────────────────────────────────
# Defaults & Colors
# ──────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
INFO="${CYAN}==>${NC}"; WARN="${YELLOW}==>${NC}"; OK="${GREEN}==>${NC}"; ERR="${RED}==>${NC}"

# Deployment names are limited to 64 characters.
MAX_NAME_LEN=64

FILES=()
RG=""
LOCATION=""
SUBSCRIPTION=""
WHAT_IF=false
YES=false
TMP_DIR=""

# Parameters given with -p, as parallel arrays (no associative arrays in bash 3.2).
CLI_KEYS=()
CLI_VALS=()

# Parameters found in the Bicep files, as parallel arrays.
P_NAMES=()
P_TYPES=()
P_DEFAULTS=()
P_VALUES=()

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

die() {
  echo -e "${ERR} $*" >&2
  exit 1
}

# ──────────────────────────────────────────────
# Detect if running interactively
# ──────────────────────────────────────────────
is_interactive() {
  [[ -t 0 && -t 1 ]]
}

# ──────────────────────────────────────────────
# Usage
# ──────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -f, --file <path>          Path to a .bicep file (may be specified multiple times)
  -g, --resource-group <rg>  Azure resource group name
  -l, --location <location>  Azure region for RG creation (e.g. eastus)
  -s, --subscription <sub>   Azure subscription ID or name
  -p, --param <key=value>    Set a Bicep parameter value (may be specified multiple times)
  --what-if                  Run what-if preview only (no deployment)
  --yes                      Skip all confirmation prompts
  -h, --help                 Show this help message

The 'workspace' parameter is the Log Analytics workspace NAME (not its
resource ID); the workspace must live in the target resource group.

Examples:
  # Interactive mode:
  $(basename "$0")

  # Fully automated:
  $(basename "$0") --file rule.bicep -g my-rg -s my-sub -p workspace=my-law --yes
EOF
}

# ──────────────────────────────────────────────
# Parse arguments
# ──────────────────────────────────────────────
need_arg() {
  # need_arg <option> <remaining arg count>
  if [[ "$2" -lt 2 ]]; then
    echo -e "${ERR} Option $1 requires a value." >&2
    usage >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file)           need_arg "$1" $#; FILES+=("$2"); shift 2 ;;
    -g|--resource-group) need_arg "$1" $#; RG="$2"; shift 2 ;;
    -l|--location)       need_arg "$1" $#; LOCATION="$2"; shift 2 ;;
    -s|--subscription)   need_arg "$1" $#; SUBSCRIPTION="$2"; shift 2 ;;
    -p|--param)
      need_arg "$1" $#
      if [[ "$2" != *"="* ]]; then
        echo -e "${ERR} $1 requires key=value format, got: $2" >&2
        exit 2
      fi
      CLI_KEYS+=("${2%%=*}")
      CLI_VALS+=("${2#*=}")
      shift 2 ;;
    --what-if)           WHAT_IF=true; shift ;;
    --yes)               YES=true; shift ;;
    -h|--help)           usage; exit 0 ;;
    *)
      echo -e "${ERR} Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# ──────────────────────────────────────────────
# Prerequisites
# ──────────────────────────────────────────────
check_prereqs() {
  command -v az &>/dev/null ||
    die "Azure CLI (az) is not installed. Install it from https://aka.ms/installazurecli"

  az account show &>/dev/null ||
    die "Not logged in to Azure. Run 'az login' first."

  if ! az bicep version &>/dev/null; then
    echo -e "${INFO} Installing Bicep CLI..."
    az bicep install
  fi
}

# ──────────────────────────────────────────────
# Prompt helpers (interactive only)
# ──────────────────────────────────────────────
prompt_required() {
  local var_name="$1" prompt_text="$2" default_val="${3:-}" val=""
  while true; do
    if [[ -n "$default_val" ]]; then
      read -r -p "$prompt_text [$default_val]: " val
      val="${val:-$default_val}"
    else
      read -r -p "$prompt_text: " val
    fi
    if [[ -n "$val" ]]; then
      printf -v "$var_name" '%s' "$val"
      return 0
    fi
    echo -e "${WARN} This value is required."
  done
}

prompt_optional() {
  local var_name="$1" prompt_text="$2" default_val="${3:-}" val=""
  read -r -p "$prompt_text [$default_val]: " val
  val="${val:-$default_val}"
  printf -v "$var_name" '%s' "$val"
}

confirm_or_yes() {
  local prompt_text="$1"
  if [[ "$YES" == true ]]; then
    return 0
  fi
  local reply
  read -r -p "$prompt_text [y/N]: " reply
  case "$reply" in
    [yY][eE][sS]|[yY]) return 0 ;;
    *) return 1 ;;
  esac
}

# ──────────────────────────────────────────────
# Error out if in non-interactive mode and a value is missing
# ──────────────────────────────────────────────
require_value() {
  local var_name="$1" label="$2" flag="$3"
  if [[ -z "${!var_name:-}" ]]; then
    die "$label is required but was not provided. Use --$flag <value> or run interactively."
  fi
}

# ──────────────────────────────────────────────
# Bicep parameter parsing
# ──────────────────────────────────────────────

# parse_bicep_params <file>: prints one "name<TAB>type<TAB>default" line per
# top-level 'param' declaration. Only string literal defaults ('...') and
# plain int/bool literals are understood; any other default expression is
# reported as "no default", so a value has to be supplied.
parse_bicep_params() {
  local file="$1" line name type rest default
  local re_param='^[[:space:]]*param[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+([A-Za-z]+)[[:space:]]*(=[[:space:]]*(.*))?$'
  local re_string="^'(([^'\\\\]|\\\\.)*)'[[:space:]]*(//.*)?$"
  local re_literal='^(-?[0-9]+|true|false)[[:space:]]*(//.*)?$'

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ $re_param ]] || continue
    name="${BASH_REMATCH[1]}"
    type="${BASH_REMATCH[2]}"
    rest="${BASH_REMATCH[4]:-}"
    default=""

    if [[ "$rest" =~ $re_string ]]; then
      default="${BASH_REMATCH[1]}"
      # Undo the escapes Bicep allows in a single-quoted string.
      default="${default//\\\'/\'}"
      default="${default//\\\\/\\}"
    elif [[ "$rest" =~ $re_literal ]]; then
      default="${BASH_REMATCH[1]}"
    fi

    printf '%s\t%s\t%s\n' "$name" "$type" "$default"
  done <"$file"
}

# param_index <name>: prints the index of a collected parameter, or returns 1.
param_index() {
  local i
  for ((i = 0; i < ${#P_NAMES[@]}; i++)); do
    if [[ "${P_NAMES[$i]}" == "$1" ]]; then
      echo "$i"
      return 0
    fi
  done
  return 1
}

# cli_param <name>: prints the value given with -p and returns 0, or returns 1.
# The last occurrence wins.
cli_param() {
  local i found=1 val=""
  for ((i = 0; i < ${#CLI_KEYS[@]}; i++)); do
    if [[ "${CLI_KEYS[$i]}" == "$1" ]]; then
      val="${CLI_VALS[$i]}"
      found=0
    fi
  done
  [[ $found -eq 0 ]] && printf '%s' "$val"
  return $found
}

# ──────────────────────────────────────────────
# Collect Bicep files
# ──────────────────────────────────────────────
abs_path() {
  # Portable realpath for an existing file.
  local dir
  dir="$(cd "$(dirname "$1")" && pwd -P)"
  printf '%s/%s' "$dir" "$(basename "$1")"
}

collect_files() {
  local f
  if [[ ${#FILES[@]} -eq 0 ]]; then
    is_interactive || die "No .bicep file specified. Use -f <path>."
    prompt_required f "Path to .bicep file"
    FILES+=("$f")
  fi

  local resolved=()
  for f in "${FILES[@]}"; do
    [[ -f "$f" ]] || die "File not found: $f"
    if [[ "$f" != *.bicep ]]; then
      echo -e "${WARN} File is not a .bicep file: $f"
    fi
    resolved+=("$(abs_path "$f")")
  done
  FILES=("${resolved[@]}")
}

# ──────────────────────────────────────────────
# Collect deployment target
# ──────────────────────────────────────────────
collect_target() {
  local current_sub
  current_sub=$(az account show --query "id" -o tsv 2>/dev/null || echo "")

  if [[ -z "$SUBSCRIPTION" ]] && is_interactive; then
    prompt_optional SUBSCRIPTION "Azure subscription ID" "$current_sub"
  fi
  require_value SUBSCRIPTION "Subscription" "subscription"
  az account set --subscription "$SUBSCRIPTION" 2>/dev/null ||
    die "Failed to set subscription to '$SUBSCRIPTION'"
  echo -e "${INFO} Using subscription: $(az account show --query "name" -o tsv)"

  if [[ -z "$RG" ]] && is_interactive; then
    prompt_required RG "Resource group name"
  fi
  require_value RG "Resource group" "resource-group"

  # Check if resource group exists
  if ! az group show --name "$RG" &>/dev/null; then
    echo -e "${WARN} Resource group '$RG' does not exist."
    if confirm_or_yes "Create resource group '$RG'?"; then
      if [[ -z "$LOCATION" ]]; then
        if is_interactive; then
          prompt_required LOCATION "Location (e.g. eastus)"
        else
          die "Resource group '$RG' does not exist and location is required. Use --location."
        fi
      fi
      az group create --name "$RG" --location "$LOCATION" --output table
      echo -e "${OK} Resource group '$RG' created in '$LOCATION'."
    else
      die "Resource group '$RG' is required but does not exist."
    fi
  fi
}

# ──────────────────────────────────────────────
# Collect parameter values (interactive + CLI)
# ──────────────────────────────────────────────
collect_param_values() {
  echo -e "${INFO} Collecting parameter values from Bicep files..."
  local f name type default_val
  for f in "${FILES[@]}"; do
    while IFS=$'\t' read -r name type default_val; do
      [[ -n "$name" ]] || continue
      if ! param_index "$name" >/dev/null; then
        P_NAMES+=("$name")
        P_TYPES+=("$type")
        P_DEFAULTS+=("$default_val")
        P_VALUES+=("")
      fi
    done < <(parse_bicep_params "$f")
  done

  if [[ ${#P_NAMES[@]} -eq 0 ]]; then
    echo -e "${WARN} No parameters found in any Bicep files."
    return
  fi

  local i value
  for ((i = 0; i < ${#P_NAMES[@]}; i++)); do
    name="${P_NAMES[$i]}"
    type="${P_TYPES[$i]}"
    default_val="${P_DEFAULTS[$i]}"
    value=""   # never carry a value over from the previous parameter

    if value="$(cli_param "$name")"; then
      # 1. CLI-provided value
      echo -e "${INFO} Using CLI-provided '$name' = '$value'"
    else
      value=""
      # 2. Default from the Bicep file
      if [[ -n "$default_val" ]]; then
        value="$default_val"
      fi
      # 3. Interactive prompt (if available)
      if is_interactive; then
        local prompt_text="Value for '$name' ($type)"
        if [[ -n "$default_val" ]]; then
          prompt_optional value "$prompt_text" "$default_val"
        else
          prompt_required value "$prompt_text"
        fi
      fi
    fi

    if [[ -z "$value" ]]; then
      die "No value provided for parameter '$name'. Use -p $name=<value> or run interactively."
    fi
    if [[ "$name" == "workspace" && "$value" == */* ]]; then
      die "Parameter 'workspace' must be the workspace name, not a resource ID (got '$value')."
    fi

    P_VALUES[$i]="$value"
  done
}

# ──────────────────────────────────────────────
# Build parent Bicep with module references
# ──────────────────────────────────────────────

# rel_path <from_dir> <to_file>: relative path between two absolute paths,
# without relying on 'realpath --relative-to'.
rel_path() {
  local from="${1%/}" to="$2"
  local common="$from" up=""
  while [[ "$to" != "$common"/* && "$common" != "" ]]; do
    common="${common%/*}"
    up="../$up"
  done
  printf '%s%s' "$up" "${to#"$common"/}"
}

build_parent_bicep() {
  local parent_file="$1"
  echo -e "${INFO} Building parent Bicep template..."

  {
    echo "targetScope = 'resourceGroup'"
    echo ""
  } >"$parent_file"

  # Values are passed with --parameters at deployment time, so they never
  # have to be quoted into the template.
  local i
  for ((i = 0; i < ${#P_NAMES[@]}; i++)); do
    echo "param ${P_NAMES[$i]} ${P_TYPES[$i]}" >>"$parent_file"
  done
  echo "" >>"$parent_file"

  local idx=0 f base mod_name rel line pname ptype pdefault
  for f in "${FILES[@]}"; do
    base="$(basename "$f" .bicep)"
    mod_name="rule_${idx}_${base}"
    mod_name="$(printf '%s' "$mod_name" | sed 's/[^a-zA-Z0-9_]/_/g')"
    mod_name="${mod_name:0:$MAX_NAME_LEN}"

    rel="$(rel_path "$(dirname "$parent_file")" "$f")"

    {
      echo "module $mod_name '$rel' = {"
      echo "  name: '$mod_name'"
      echo "  params: {"
    } >>"$parent_file"

    while IFS=$'\t' read -r pname ptype pdefault; do
      [[ -n "$pname" ]] || continue
      echo "    $pname: $pname" >>"$parent_file"
    done < <(parse_bicep_params "$f")

    {
      echo "  }"
      echo "}"
      echo ""
    } >>"$parent_file"

    idx=$((idx + 1))
  done
}

# ──────────────────────────────────────────────
# Deploy
# ──────────────────────────────────────────────
do_deploy() {
  local deployment_name deployment_name_sanitized
  if [[ ${#FILES[@]} -eq 1 ]]; then
    deployment_name=$(basename "${FILES[0]}" .bicep)
  else
    deployment_name="sentinel-rules-batch"
  fi
  # Leave room for the "-<epoch>" suffix.
  deployment_name_sanitized=$(printf '%s' "$deployment_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]/-/g' | cut -c1-$((MAX_NAME_LEN - 11)))

  TMP_DIR=$(mktemp -d)

  local parent_bicep="$TMP_DIR/main.bicep"
  local arm_json="$TMP_DIR/main.json"

  build_parent_bicep "$parent_bicep"

  echo -e "${INFO} Compiling Bicep to ARM..."
  az bicep build --file "$parent_bicep" --outfile "$arm_json" ||
    die "Bicep compilation failed."
  echo -e "${OK} Bicep compiled successfully."

  # --parameters name=value, passed as separate arguments so no quoting is needed.
  local param_args=() i
  if [[ ${#P_NAMES[@]} -gt 0 ]]; then
    param_args+=(--parameters)
    for ((i = 0; i < ${#P_NAMES[@]}; i++)); do
      param_args+=("${P_NAMES[$i]}=${P_VALUES[$i]}")
    done
  fi

  echo -e "${INFO} Running deployment what-if preview..."
  az deployment group what-if \
    --resource-group "$RG" \
    --template-file "$arm_json" \
    ${param_args[@]+"${param_args[@]}"} \
    --output table ||
    die "What-if failed (see above). Nothing was deployed."

  if [[ "$WHAT_IF" == true ]]; then
    echo -e "${OK} What-if preview complete. Skipping deployment (--what-if mode)."
    echo ""
    echo "Deployment files:"
    printf '  - %s\n' "${FILES[@]}"
    echo "Resource group: $RG"
    echo ""
    return 0
  fi

  echo ""
  if ! confirm_or_yes "Proceed with deployment?"; then
    echo -e "${WARN} Deployment cancelled."
    return 0
  fi

  echo -e "${INFO} Deploying to resource group '$RG'..."
  local provisioning_state
  provisioning_state=$(az deployment group create \
    --resource-group "$RG" \
    --name "$deployment_name_sanitized-$(date +%s)" \
    --template-file "$arm_json" \
    ${param_args[@]+"${param_args[@]}"} \
    --query 'properties.provisioningState' \
    --output tsv) || die "Deployment failed."

  echo ""
  echo -e "${OK} Deployment: ${GREEN}${provisioning_state:-unknown}${NC}"
  echo ""
  echo "Summary:"
  echo "  Resource group:  $RG"
  echo "  Subscription:    $(az account show --query 'name' -o tsv)"
  echo "  Alert rules deployed:"
  local f
  for f in "${FILES[@]}"; do
    echo "    - $(basename "$f" .bicep)"
  done
  echo ""

  if [[ "$provisioning_state" == "Succeeded" ]]; then
    echo -e "${OK} All alert rules deployed successfully."
  else
    echo -e "${WARN} Deployment state: ${provisioning_state:-unknown}. Check the Azure portal for details."
    exit 1
  fi
}

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Sentinel Bicep Deployment Script   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

check_prereqs
collect_files
collect_target
collect_param_values
do_deploy
