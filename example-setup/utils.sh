#!/bin/bash

# Returns the absolute path
abs_path() {
  if [[ -d "$(dirname "$1")" ]]
  then
    echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" || true
  fi
}

# Updates the JSON data given in the first argument through setting the key and
# value given in the second and third argument. Numbers must be \"\" quoted,
# if they should be treated as a JSON string
setjson() {
  if [[ "$#" -ne 3 ]]; then
    echo "Error: provided invalid number of parameters: $#: $@"
    echo "Usage: setjson <json-input> <key> <value>"
    return 1
  fi

  local -n ref=$1
  local key=$2
  local value=$3

  if [[ "${value}" == \"*\" || "${value}" == \'*\' ]]; then
    # Parameter is string in quotes, use as is
    ref="$(echo "${ref}" | jq ".${key} = ${value}")"
  elif [[ "${value}" =~ ^\{.*\}$ || "${value}" =~ ^\[.*\]$ ]]; then
    # Parameter is a JSON object or array, do not use quotes
    ref="$(echo "${ref}" | jq ".${key} = ${value}")"
  elif [[ "${value}" =~ ^[0-9]+$ || "${value}" == "true" || "${value}" == "false" ]]; then
    # Parameter is number or boolean, do not use quotes
    ref="$(echo "${ref}" | jq ".${key} = ${value}")"
  else
    # Parameter is a string, wrap in quotes
    ref="$(echo "${ref}" | jq ".${key} = \"${value}\"")"
  fi
}

# Updates the JSON data given in the first argument through setting the array given
# in the second argument to the value given in the third argument. Can handle entire
# arrays and single values
setarr() {
  if [[ "$#" -lt 3 ]]; then
    echo "Error: provided invalid number of parameters: $#: $@"
    echo "Usage: setarr <json-input> <key> <value>"
    return 1
  fi

  local -n ref=$1
  shift
	local key=$1
  shift
  local value=$1

  # Delete any existing values
  ref="$(echo "${ref}" | jq "del(.${key}[])")"

  # Insert new values
  if echo "${value}" | jq -e 'type == "array"' >/dev/null 2>&1; then
    # A whole array is passed
    ref="$(echo "${ref}" | jq --argjson ver "${value}" '.referenceValues += $ver')"
  else
    # Single parameters are passed
    for param in "$@"; do
      ref="$(echo "${ref}" | jq ".${key} += [\"${param}\"]")"
    done
  fi
}

# Updates the JSON data given in the first argument through extending the array
# given in the second argument with the value given in the third argument
extendarr() {
  if [[ "$#" -ne 3 ]]; then
    echo "Error: provided invalid number of parameters: $#: $@"
    echo "Usage: extendarr <json-input> <key> <value>"
    return 1
  fi

  local -n ref=$1
	local key=$2
  local param=$3

  # Add new value
  ref="$(echo "${ref}" | jq ".${key} += [${param}]")"
}