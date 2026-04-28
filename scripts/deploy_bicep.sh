#!/usr/bin/env bash
# Interactive Bicep deployment script for Sentinel alert rules
# Deploys one or more .bicep files to a resource group in a single deployment.
set -euo pipefail

# ──────────────────────────────────────────────
# Defaults & Colors
# ──────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
INFO="${CYAN}==>${NC}"; WARN="${YELLOW}==>${NC}"; OK="${GREEN}==>${NC}"; ERR="${RED}==>${NC}"

FILES=()
RG=""
LOCATION=""
SUBSCRIPTION=""
WHAT_IF=false
YES=false
declare -A CLI_PARAMS

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

Examples:
  # Interactive mode:
  $(basename "$0")

  # Fully automated:
  $(basename "$0") --file rule.bicep -g my-rg -s my-sub -p workspace=/subscriptions/.../workspaces/my-law --yes
EOF
  exit 0
}

# ──────────────────────────────────────────────
# Parse arguments
# ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file)       FILES+=("$2"); shift 2 ;;
    -g|--resource-group) RG="$2"; shift 2 ;;
    -l|--location) LOCATION="$2"; shift 2 ;;
    -s|--subscription) SUBSCRIPTION="$2"; shift 2 ;;
    -p|--param)
      if [[ "$2" != *"="* ]]; then
        echo -e "${ERR} -p requires key=value format, got: $2"
        exit 1
      fi
      key="${2%%=*}"
      val="${2#*=}"
      CLI_PARAMS["$key"]="$val"
      shift 2 ;;
    --what-if)       WHAT_IF=true; shift ;;
    --yes)           YES=true; shift ;;
    -h|--help)       usage ;;
    *)
      echo -e "${ERR} Unknown option: $1"
      usage
      ;;
  esac
done

# ──────────────────────────────────────────────
# Prerequisites
# ──────────────────────────────────────────────
check_prereqs() {
  if ! command -v az &>/dev/null; then
    echo -e "${ERR} Azure CLI (az) is not installed. Install it from https://aka.ms/installazurecli"
    exit 1
  fi

  if ! az account show &>/dev/null; then
    echo -e "${ERR} Not logged in to Azure. Run 'az login' first."
    exit 1
  fi

  if ! az bicep show &>/dev/null 2>&1; then
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
      eval "$var_name=\"\$val\""
      return 0
    fi
    echo -e "${WARN} This value is required."
  done
}

prompt_optional() {
  local var_name="$1" prompt_text="$2" default_val="${3:-}" val=""
  read -r -p "$prompt_text [$default_val]: " val
  val="${val:-$default_val}"
  eval "$var_name=\"\$val\""
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
  local var_name="$1" label="$2"
  if [[ -z "${!var_name:-}" ]]; then
    echo -e "${ERR} $label is required but was not provided. Use --$3 <value> or run interactively."
    exit 1
  fi
}

# ──────────────────────────────────────────────
# Parse Bicep parameters from a file
# ──────────────────────────────────────────────
parse_bicep_params() {
  local file="$1"
  grep -E '^\s*param\s+' "$file" 2>/dev/null || true
}

# ──────────────────────────────────────────────
# Collect Bicep files
# ──────────────────────────────────────────────
collect_files() {
  if [[ ${#FILES[@]} -eq 0 ]]; then
    if ! is_interactive; then
      echo -e "${ERR} No .bicep file specified. Use -f <path>."
      exit 1
    fi
    local f
    prompt_required f "Path to .bicep file"
    FILES+=("$f")
  fi

  local resolved=()
  for f in "${FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
      echo -e "${ERR} File not found: $f"
      exit 1
    fi
    if [[ "$f" != *.bicep ]]; then
      echo -e "${WARN} File is not a .bicep file: $f"
    fi
    resolved+=("$(realpath "$f")")
  done
  FILES=("${resolved[@]}")
}

# ──────────────────────────────────────────────
# Collect deployment target
# ──────────────────────────────────────────────
collect_target() {
  local current_sub
  current_sub=$(az account show --query "id" -o tsv 2>/dev/null || echo "")

  if [[ -z "$SUBSCRIPTION" ]]; then
    if is_interactive; then
      prompt_optional SUBSCRIPTION "Azure subscription ID" "$current_sub"
    fi
  fi
  require_value SUBSCRIPTION "Subscription" "subscription"
  az account set --subscription "$SUBSCRIPTION" 2>/dev/null || {
    echo -e "${ERR} Failed to set subscription to '$SUBSCRIPTION'"
    exit 1
  }
  echo -e "${INFO} Using subscription: $(az account show --query "name" -o tsv)"

  if [[ -z "$RG" ]]; then
    if is_interactive; then
      prompt_required RG "Resource group name"
    fi
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
          echo -e "${ERR} Resource group '$RG' does not exist and location is required. Use --location."
          exit 1
        fi
      fi
      az group create --name "$RG" --location "$LOCATION" --output table
      echo -e "${OK} Resource group '$RG' created in '$LOCATION'."
    else
      echo -e "${ERR} Resource group '$RG' is required but does not exist."
      exit 1
    fi
  fi
}

# ──────────────────────────────────────────────
# Collect parameter values (interactive + CLI)
# ──────────────────────────────────────────────
declare -A PARAM_VALUES

collect_param_values() {
  echo -e "${INFO} Collecting parameter values from Bicep files..."
  local all_params=()
  for f in "${FILES[@]}"; do
    while IFS= read -r line; do
      local name type default_val
      name=$(echo "$line" | awk '{print $2}')
      type=$(echo "$line" | awk '{print $3}')
      default_val=$(echo "$line" | grep -oP '=\s*\K\S+' || true)
      default_val="${default_val%\"}"
      default_val="${default_val#\"}"
      if [[ ! -v PARAM_VALUES["$name"] ]]; then
        PARAM_VALUES["$name"]=""
        all_params+=("$name:$type:$default_val")
      fi
    done < <(parse_bicep_params "$f")
  done

  if [[ ${#all_params[@]} -eq 0 ]]; then
    echo -e "${WARN} No parameters found in any Bicep files."
    return
  fi

  for entry in "${all_params[@]}"; do
    local name type default_val value
    name=$(echo "$entry" | cut -d: -f1)
    type=$(echo "$entry" | cut -d: -f2)
    default_val=$(echo "$entry" | cut -d: -f3-)

    # 1. Check CLI-provided params first
    if [[ -v CLI_PARAMS["$name"] ]]; then
      value="${CLI_PARAMS["$name"]}"
      echo -e "${INFO} Using CLI-provided '$name' = '$value'"
    else
      # 2. Default from Bicep file
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

    if [[ -z "${value:-}" ]]; then
      echo -e "${ERR} No value provided for parameter '$name'. Use -p $name=<value> or run interactively."
      exit 1
    fi

    PARAM_VALUES["$name"]="$value"
  done
}

# ──────────────────────────────────────────────
# Build parent Bicep with module references
# ──────────────────────────────────────────────
build_parent_bicep() {
  local parent_file="$1"
  echo -e "${INFO} Building parent Bicep template..."

  cat > "$parent_file" <<'BIICEP_HEADER'
targetScope = 'resourceGroup'

BIICEP_HEADER

  for name in "${!PARAM_VALUES[@]}"; do
    echo "param $name string" >> "$parent_file"
  done
  echo "" >> "$parent_file"

  local idx=0
  for f in "${FILES[@]}"; do
    local basename
    basename=$(basename "$f" .bicep)
    local mod_name="rule_${idx}_${basename}"
    mod_name=$(echo "$mod_name" | sed 's/[^a-zA-Z0-9_]/_/g')

    local rel_path
    rel_path=$(realpath --relative-to="$(dirname "$parent_file")" "$f")

    cat >> "$parent_file" <<BIICEP_MODULE

module $mod_name '$rel_path' = {
  name: '$mod_name'
  params: {
BIICEP_MODULE

    while IFS= read -r line; do
      local pname
      pname=$(echo "$line" | awk '{print $2}')
      echo "    $pname: '${PARAM_VALUES[$pname]}'" >> "$parent_file"
    done < <(parse_bicep_params "$f")

    echo "  }" >> "$parent_file"
    echo "}" >> "$parent_file"

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
  deployment_name_sanitized=$(echo "$deployment_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]/-/g' | cut -c1-64)

  local tmp_dir
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir"' EXIT

  local parent_bicep="$tmp_dir/main.bicep"
  local arm_json="$tmp_dir/main.json"

  build_parent_bicep "$parent_bicep"

  echo -e "${INFO} Compiling Bicep to ARM..."
  if ! az bicep build --file "$parent_bicep" --outfile "$arm_json" 2>&1; then
    echo -e "${ERR} Bicep compilation failed."
    exit 1
  fi
  echo -e "${OK} Bicep compiled successfully."

  echo -e "${INFO} Running deployment what-if preview..."
  az deployment group what-if \
    --resource-group "$RG" \
    --template-file "$arm_json" \
    --output table 2>&1 || {
    echo -e "${WARN} What-if completed with warnings (see above)."
  }

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
  local deploy_output
  deploy_output=$(az deployment group create \
    --resource-group "$RG" \
    --name "$deployment_name_sanitized-$(date +%s)" \
    --template-file "$arm_json" \
    --output json 2>&1) || {
    echo -e "${ERR} Deployment failed."
    echo "$deploy_output"
    exit 1
  }

  local provisioning_state
  provisioning_state=$(echo "$deploy_output" | jq -r '.properties.provisioningState' 2>/dev/null || echo "unknown")

  echo ""
  echo -e "${OK} Deployment: ${GREEN}$provisioning_state${NC}"
  echo ""
  echo "Summary:"
  echo "  Resource group:  $RG"
  echo "  Subscription:    $(az account show --query 'name' -o tsv)"
  echo "  Alert rules deployed:"
  for f in "${FILES[@]}"; do
    echo "    - $(basename "$f" .bicep)"
  done
  echo ""

  if [[ "$provisioning_state" == "Succeeded" ]]; then
    echo -e "${OK} All alert rules deployed successfully."
  else
    echo -e "${WARN} Deployment state: $provisioning_state. Check the Azure portal for details."
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
